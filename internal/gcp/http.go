// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"container/list"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/go-logr/logr"
	"github.com/oakwood-commons/httpc"
)

// Default HTTP client settings.
const (
	defaultHTTPTimeout         = 30 * time.Second
	defaultHTTPRetryMax        = 3
	defaultHTTPRetryWaitFloor  = 1 * time.Second
	defaultHTTPRetryWaitMax    = 10 * time.Second
	defaultHTTPClientCacheSize = 32
	maxTokenResponseBytes      = 1 << 20 // 1 MiB cap on token/error/userinfo responses
)

// HTTPClient abstracts HTTP calls for testability.
type HTTPClient interface {
	// PostForm sends a POST request with form-encoded body and returns the response.
	PostForm(ctx context.Context, url string, data url.Values) (*http.Response, error)

	// Get sends a GET request with the given headers and returns the response.
	Get(ctx context.Context, url string, headers map[string]string) (*http.Response, error)

	// Do sends an arbitrary HTTP request.
	Do(ctx context.Context, req *http.Request) (*http.Response, error)
}

func boolPtr(b bool) *bool { return &b }

// mergeHTTPClientDefaults overlays cfg on top of the plugin's auth-safe HTTP
// defaults (caching and compression disabled unless explicitly overridden).
func mergeHTTPClientDefaults(cfg *httpc.AppConfig) *httpc.AppConfig {
	base := &httpc.AppConfig{
		Timeout:           defaultHTTPTimeout.String(),
		RetryMax:          defaultHTTPRetryMax,
		RetryWaitMin:      defaultHTTPRetryWaitFloor.String(),
		RetryWaitMax:      defaultHTTPRetryWaitMax.String(),
		EnableCache:       boolPtr(false),
		EnableCompression: boolPtr(false),
	}
	return httpc.MergeAppConfig(base, cfg)
}

// effectiveHTTPConfigKey is a comparable canonical representation of a merged
// httpc.ClientConfig so semantically equivalent per-RPC httpClient settings
// share a single cached client (preserving connection pools and circuit-breaker
// state across RPCs).
type effectiveHTTPConfigKey struct {
	timeout                           time.Duration
	retryMax                          int
	retryWaitMin                      time.Duration
	retryWaitMax                      time.Duration
	enableCache                       bool
	cacheType                         httpc.CacheType
	cacheDir                          string
	cacheTTL                          time.Duration
	cacheKeyPrefix                    string
	maxCacheFileSize                  int64
	memoryCacheSize                   int
	enableCircuitBreaker              bool
	circuitBreakerMaxFailures         int
	circuitBreakerOpenTimeout         time.Duration
	circuitBreakerHalfOpenMaxRequests int
	enableCompression                 bool
	allowPrivateIPs                   bool
	maxResponseBodySize               int64
}

func effectiveHTTPConfigKeyFromClientConfig(cfg *httpc.ClientConfig) effectiveHTTPConfigKey {
	k := effectiveHTTPConfigKey{
		timeout:              cfg.Timeout,
		retryMax:             cfg.RetryMax,
		retryWaitMin:         cfg.RetryWaitMin,
		retryWaitMax:         cfg.RetryWaitMax,
		enableCache:          cfg.EnableCache,
		enableCircuitBreaker: cfg.EnableCircuitBreaker,
		enableCompression:    cfg.EnableCompression,
		allowPrivateIPs:      cfg.AllowPrivateIPs,
		maxResponseBodySize:  cfg.MaxResponseBodySize,
	}
	if cfg.EnableCache {
		k.cacheType = cfg.CacheType
		k.cacheTTL = cfg.CacheTTL
		if cfg.CacheType == httpc.CacheTypeFilesystem {
			k.cacheDir = cfg.CacheDir
			k.cacheKeyPrefix = cfg.CacheKeyPrefix
			k.maxCacheFileSize = cfg.MaxCacheFileSize
		} else {
			k.memoryCacheSize = cfg.MemoryCacheSize
		}
	}
	if cfg.EnableCircuitBreaker && cfg.CircuitBreakerConfig != nil {
		k.circuitBreakerMaxFailures = cfg.CircuitBreakerConfig.MaxFailures
		k.circuitBreakerOpenTimeout = cfg.CircuitBreakerConfig.OpenTimeout
		k.circuitBreakerHalfOpenMaxRequests = cfg.CircuitBreakerConfig.HalfOpenMaxRequests
	}
	return k
}

// resolveEffectiveHTTPConfig merges plugin defaults with cfg, validates all
// duration and enum fields using the same rules as httpc.NewClientFromAppConfig,
// and returns both the canonical cache key and the resolved ClientConfig.
func resolveEffectiveHTTPConfig(cfg *httpc.AppConfig) (effectiveHTTPConfigKey, *httpc.ClientConfig, error) {
	merged := mergeHTTPClientDefaults(cfg)
	clientCfg := httpc.DefaultConfig()

	if merged.Timeout != "" {
		d, err := time.ParseDuration(merged.Timeout)
		if err != nil {
			return effectiveHTTPConfigKey{}, nil, fmt.Errorf("invalid timeout duration %q: %w", merged.Timeout, err)
		}
		clientCfg.Timeout = d
	}
	if merged.RetryMax > 0 {
		clientCfg.RetryMax = merged.RetryMax
	}
	if merged.RetryWaitMin != "" {
		d, err := time.ParseDuration(merged.RetryWaitMin)
		if err != nil {
			return effectiveHTTPConfigKey{}, nil, fmt.Errorf("invalid retryWaitMin duration %q: %w", merged.RetryWaitMin, err)
		}
		clientCfg.RetryWaitMin = d
	}
	if merged.RetryWaitMax != "" {
		d, err := time.ParseDuration(merged.RetryWaitMax)
		if err != nil {
			return effectiveHTTPConfigKey{}, nil, fmt.Errorf("invalid retryWaitMax duration %q: %w", merged.RetryWaitMax, err)
		}
		clientCfg.RetryWaitMax = d
	}
	if merged.EnableCache != nil {
		clientCfg.EnableCache = *merged.EnableCache
	}
	if merged.CacheType != "" {
		ct := httpc.CacheType(merged.CacheType)
		if ct != httpc.CacheTypeMemory && ct != httpc.CacheTypeFilesystem {
			return effectiveHTTPConfigKey{}, nil, fmt.Errorf("invalid cacheType %q: must be %q or %q", merged.CacheType, httpc.CacheTypeMemory, httpc.CacheTypeFilesystem)
		}
		clientCfg.CacheType = ct
	}
	if merged.CacheDir != "" {
		clientCfg.CacheDir = merged.CacheDir
	}
	if merged.CacheTTL != "" {
		d, err := time.ParseDuration(merged.CacheTTL)
		if err != nil {
			return effectiveHTTPConfigKey{}, nil, fmt.Errorf("invalid cacheTTL duration %q: %w", merged.CacheTTL, err)
		}
		clientCfg.CacheTTL = d
	}
	if merged.CacheKeyPrefix != "" {
		clientCfg.CacheKeyPrefix = merged.CacheKeyPrefix
	}
	if merged.MaxCacheFileSize > 0 {
		clientCfg.MaxCacheFileSize = merged.MaxCacheFileSize
	}
	if merged.MemoryCacheSize > 0 {
		clientCfg.MemoryCacheSize = merged.MemoryCacheSize
	}
	if merged.EnableCircuitBreaker != nil {
		clientCfg.EnableCircuitBreaker = *merged.EnableCircuitBreaker
	}
	if merged.CircuitBreakerMaxFailures > 0 || merged.CircuitBreakerOpenTimeout != "" || merged.CircuitBreakerHalfOpenMaxRequests > 0 {
		clientCfg.CircuitBreakerConfig = httpc.DefaultCircuitBreakerConfig()
		if merged.CircuitBreakerMaxFailures > 0 {
			clientCfg.CircuitBreakerConfig.MaxFailures = merged.CircuitBreakerMaxFailures
		}
		if merged.CircuitBreakerOpenTimeout != "" {
			d, err := time.ParseDuration(merged.CircuitBreakerOpenTimeout)
			if err != nil {
				return effectiveHTTPConfigKey{}, nil, fmt.Errorf("invalid circuitBreakerOpenTimeout duration %q: %w", merged.CircuitBreakerOpenTimeout, err)
			}
			clientCfg.CircuitBreakerConfig.OpenTimeout = d
		}
		if merged.CircuitBreakerHalfOpenMaxRequests > 0 {
			clientCfg.CircuitBreakerConfig.HalfOpenMaxRequests = merged.CircuitBreakerHalfOpenMaxRequests
		}
	}
	if merged.EnableCompression != nil {
		clientCfg.EnableCompression = *merged.EnableCompression
	}
	if merged.AllowPrivateIPs != nil {
		clientCfg.AllowPrivateIPs = *merged.AllowPrivateIPs
	}
	if merged.MaxResponseBodySize > 0 {
		clientCfg.MaxResponseBodySize = merged.MaxResponseBodySize
	}

	return effectiveHTTPConfigKeyFromClientConfig(clientCfg), clientCfg, nil
}

func newIsolatedTransport() *http.Transport {
	if dt, ok := http.DefaultTransport.(*http.Transport); ok && dt != nil {
		return dt.Clone()
	}
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

func cloneResolvedClientConfig(baseCfg *httpc.ClientConfig, logger logr.Logger, tr *http.Transport) *httpc.ClientConfig {
	cfgCopy := *baseCfg
	if baseCfg.CircuitBreakerConfig != nil {
		cbCopy := *baseCfg.CircuitBreakerConfig
		cfgCopy.CircuitBreakerConfig = &cbCopy
	}
	cfgCopy.Logger = logger
	cfgCopy.Transport = tr
	return &cfgCopy
}

// boundedClientCache is a concurrency-safe, size-bounded LRU cache of closable
// HTTP clients. Evicted or cleared entries have Close() invoked outside the
// cache mutex so idle transport connections and cache handles are released
// without blocking concurrent lookups.
type boundedClientCache[K comparable, V io.Closer] struct {
	mu       sync.Mutex
	capacity int
	store    map[K]*list.Element
	order    *list.List
}

type clientCacheEntry[K comparable, V io.Closer] struct {
	key   K
	value V
}

func newBoundedClientCache[K comparable, V io.Closer](capacity int) *boundedClientCache[K, V] {
	if capacity <= 0 {
		capacity = defaultHTTPClientCacheSize
	}
	return &boundedClientCache[K, V]{
		capacity: capacity,
		store:    make(map[K]*list.Element, capacity),
		order:    list.New(),
	}
}

func (c *boundedClientCache[K, V]) GetOrCreate(key K, build func() V) V {
	c.mu.Lock()
	if elem, ok := c.store[key]; ok {
		c.order.MoveToFront(elem)
		val := elem.Value.(*clientCacheEntry[K, V]).value
		c.mu.Unlock()
		return val
	}
	c.mu.Unlock()

	candidate := build()

	c.mu.Lock()
	if elem, ok := c.store[key]; ok {
		c.order.MoveToFront(elem)
		winner := elem.Value.(*clientCacheEntry[K, V]).value
		c.mu.Unlock()
		_ = candidate.Close()
		return winner
	}

	elem := c.order.PushFront(&clientCacheEntry[K, V]{key: key, value: candidate})
	c.store[key] = elem

	var evicted V
	var hasEvicted bool
	if c.order.Len() > c.capacity {
		if oldest := c.order.Back(); oldest != nil {
			entry := oldest.Value.(*clientCacheEntry[K, V])
			delete(c.store, entry.key)
			c.order.Remove(oldest)
			evicted = entry.value
			hasEvicted = true
		}
	}
	c.mu.Unlock()

	if hasEvicted {
		_ = evicted.Close()
	}
	return candidate
}

func (c *boundedClientCache[K, V]) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}

func (c *boundedClientCache[K, V]) CloseAll() {
	if c == nil {
		return
	}
	c.mu.Lock()
	toClose := make([]V, 0, c.order.Len())
	for elem := c.order.Front(); elem != nil; elem = elem.Next() {
		toClose = append(toClose, elem.Value.(*clientCacheEntry[K, V]).value)
	}
	c.store = make(map[K]*list.Element, c.capacity)
	c.order.Init()
	c.mu.Unlock()

	for _, client := range toClose {
		_ = client.Close()
	}
}

// DefaultHTTPClient is the standard HTTP client implementation backed by httpc.
// Caching is disabled by default because token-exchange responses must never
// be served from cache.
type DefaultHTTPClient struct {
	client    *httpc.Client
	transport *http.Transport
}

func newDefaultHTTPClientFromResolved(baseCfg *httpc.ClientConfig, logger logr.Logger) *DefaultHTTPClient {
	tr := newIsolatedTransport()
	return &DefaultHTTPClient{
		client:    httpc.NewClient(cloneResolvedClientConfig(baseCfg, logger, tr)),
		transport: tr,
	}
}

// NewDefaultHTTPClient creates a new DefaultHTTPClient using plugin defaults.
func NewDefaultHTTPClient(logger logr.Logger) *DefaultHTTPClient {
	_, clientCfg, _ := resolveEffectiveHTTPConfig(nil)
	return newDefaultHTTPClientFromResolved(clientCfg, logger)
}

// NewDefaultHTTPClientFromAppConfig creates a new DefaultHTTPClient with cfg
// overlaid on the plugin defaults.
func NewDefaultHTTPClientFromAppConfig(cfg *httpc.AppConfig, logger logr.Logger) (*DefaultHTTPClient, error) {
	_, clientCfg, err := resolveEffectiveHTTPConfig(cfg)
	if err != nil {
		return nil, err
	}
	return newDefaultHTTPClientFromResolved(clientCfg, logger), nil
}

// Close releases idle HTTP connections and any underlying cache resources.
func (c *DefaultHTTPClient) Close() error {
	if c == nil {
		return nil
	}
	if c.transport != nil {
		c.transport.CloseIdleConnections()
	}
	if c.client != nil {
		return c.client.Close()
	}
	return nil
}

// PostForm sends a POST request with form-encoded body.
func (c *DefaultHTTPClient) PostForm(ctx context.Context, endpoint string, data url.Values) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating POST request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return c.client.Do(req)
}

// Get sends a GET request with custom headers.
func (c *DefaultHTTPClient) Get(ctx context.Context, reqURL string, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating GET request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return c.client.Do(req)
}

// Do sends an arbitrary HTTP request.
func (c *DefaultHTTPClient) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	req = req.WithContext(ctx)
	return c.client.Do(req)
}

// sanitizeControlChars removes C0 (< 0x20), DEL (0x7f), C1 (0x80..0x9f), and
// Unicode bidirectional formatting controls from untrusted error strings while
// normalizing tabs and line breaks to single spaces so terminal escape
// sequences cannot be injected.
func sanitizeControlChars(s string) string {
	if s == "" {
		return ""
	}
	const maxRunes = 512
	var b strings.Builder
	b.Grow(min(len(s), maxRunes*utf8.UTFMax))
	count := 0
	pendingSpace := false
	for i := 0; i < len(s); {
		r, width := utf8.DecodeRuneInString(s[i:])
		i += width
		if r == utf8.RuneError && width == 1 {
			continue
		}
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\u2028' || r == '\u2029' {
			if count > 0 {
				pendingSpace = true
			}
			continue
		}
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) ||
			r == 0x061c || r == 0x200e || r == 0x200f ||
			(r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			continue
		}
		if pendingSpace {
			if count+1 >= maxRunes {
				break
			}
			b.WriteByte(' ')
			count++
			pendingSpace = false
		}
		b.WriteRune(r)
		count++
		if count >= maxRunes {
			break
		}
	}
	return b.String()
}
