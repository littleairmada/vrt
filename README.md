# vrt
[![Build Status](https://github.com/littleairmada/vrt/workflows/CI/badge.svg)](https://github.com/littleairmada/vrt/actions?query=workflows%3ACI)
[![GoDoc](https://godoc.org/github.com/littleairmada/vrt?status.svg)](https://godoc.org/github.com/littleairmada/vrt)
[![Coverage Status](https://codecov.io/gh/littleairmada/vrt/branch/master/graph/badge.svg)](https://codecov.io/gh/littleairmada/vrt)
[![GoReport](https://goreportcard.com/badge/github.com/littleairmada/vrt)](https://goreportcard.com/report/github.com/littleairmada/vrt)

## Install

```shell
go get github.com/littleairmada/vrt
```

**Note:** VRT uses [Go Modules](https://github.com/golang/go/wiki/Modules) to manage dependencies.

## What is VRT?

VRT is a basic VITA 49.0 Radio Transport (VRT) packet parsing library for Go applications.

It uses [gopacket](https://github.com/google/gopacket) and can handle the basics of parsing VRT packets & serializing VRT structs into packets. It was originally developed to support a project using [FlexRadio](https://www.flexradio.com/comparison/) Amateur Radio transceivers.

It is **not** feature complete and currently supports:

* decoding a VRT packet from a series of bytes
* serializing a VRT packet struct into a byte array for processing by [gopacket](https://github.com/google/gopacket) or another packet injection library

## How to get the library

The library is split into several parts:
* `vrt`: basic implementation of VRT packet parsing/serialization based on the VITA 49.0 specification
* `examples`: example programs that use the `vrt` library to decode or encode VRT packets

You will probably only need `vrt` explicitly. The rest is pulled in automatically if necessary.

## References

* [ANSI/VITA 49.0-2015, VITA Radio Transport (VRT) Standard](https://www.vita.com/Sys/Store/Products/258942): The VITA Radio Transport (VRT) standard defines a transport-layer protocol designed to promote interoperability between RF (radio frequency) receivers and signal processing equipment in a wide range of applications.

## License

The project is licensed under the [MIT License](LICENSE).