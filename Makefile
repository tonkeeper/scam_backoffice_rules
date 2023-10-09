.PHONY: all test 

all: test

test:
	go test $$(go list ./... | grep -v /vendor/) -race -coverprofile cover.out
