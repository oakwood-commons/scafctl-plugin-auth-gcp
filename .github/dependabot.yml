version: 2
updates:
  - package-ecosystem: gomod
    directory: /
    schedule:
      interval: weekly
    groups:
      go-dependencies:
        applies-to: version-updates
        patterns:
          - "*"
      go-security-updates:
        applies-to: security-updates
        patterns:
          - "*"
  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly
    groups:
      ci-dependencies:
        applies-to: version-updates
        patterns:
          - "*"
      ci-security-updates:
        applies-to: security-updates
        patterns:
          - "*"
