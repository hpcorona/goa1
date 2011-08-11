#!/bin/sh

export GOOS=windows
export GOARCH=386

8g -o _go_.8 goa1.go
8l -o goa1.lib _go_.8
