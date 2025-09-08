# Fast-ssh-over-https
best way for freedom

install

wget https://go.dev/dl/go1.21.2.linux-amd64.tar.gz

tar -C $HOME -xzf go1.21.2.linux-amd64.tar.gz

export PATH=$HOME/go/bin:$HOME/go/bin:$PATH

go mod init ssl

go get golang.org/x/crypto/ssh
