# commit as you
git config --local user.email "kcloutier@comcast.net"
git config --local user.name "Ken Cloutier" 

# sign commits using SSH keys
git config --local gpg.format ssh

# sign commits by default
git config --local commit.gpgsign true

# use your SSH key to sign commits:
git config --local user.signingkey ~/.ssh/id_ecdsa_public_github.pub


$Tag = "v0.6.0"
git tag $Tag -s -m "Release $Tag"
git push origin $Tag