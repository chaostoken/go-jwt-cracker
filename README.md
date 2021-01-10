# JWT HMAC256 cracker

## Installation

### CLI tool
```
go get -u github.com/chaostoken/go-jwt-cracker 
```

### Docker
```
docker build . -t jwtcracker
docker run -d --name=jwtckracker1 -e JWT_TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjo2NTQ5LCJleHAiOjE2MTExODM5MjF9.EbTsedxHGvncPc592WsXzGji-spAtVdJuJ9K8a3d1ns" jwtcracker
docker logs jwtckracker1
```
## Usage
```
go-jwt-cracker help
```