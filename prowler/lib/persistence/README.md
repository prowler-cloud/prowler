# Persistence data structures

This package contains the data structures that wraps standard Python data structures to provide persistence.

**Table of Contents**

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

- [Purpose](#purpose)
- [How it works](#how-it-works)
- [How to use](#how-to-use)
  - [Basic usage](#basic-usage)
  - [Using the non-memory based data structures](#using-the-non-memory-based-data-structures)
  - [Advanced usage for SQLite](#advanced-usage-for-sqlite)
- [Performance](#performance)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Purpose

The purpose of this package is to provide a way to persist memory data structures, like list or dict, to disk.

## How it works

This package provides a builder pattern to create a new instance of a persistence data structure.

Instead of storing the data in memory, it stores it in a file on disk. To be more specific, it stores in a database, but the behavior is the same that the original Python data structure.

Currently, the following data structures are supported:

- List
- Dict

What databases are supported? Currently, only SQLite is supported.

## How to use

### Basic usage

Usage is pretty simple. When you want to use a non-memory based data structure, you need to create a new instance of the data structure builder.

```python

from prowler.lib.persistence import mklist, mkdict

# Create a new list
a = mklist()
a.append("item1")
a.append("item2")

print(a)
print(a[0])

del a[0]

# Creating a new dict
b = mkdict()
b["key1"] = "value1"
b["key2"] = "value2"

print(b)
print(b["key1"])

del b["key1"]

print("key1" in b)
```

> Note: The above code is NOT using the SQLite database. By default, it uses native Python data structures.

### Using the non-memory based data structures

When you want to use a non-memory, this is SQLite, you need to set the `PROWLER_DB_CONNECTION` environment variable to `sqlite://`.

For example:

```bash
> export PROWLER_DB_CONNECTION=sqlite://
```


### Advanced usage for SQLite

When you want to set the SQLite cache size, you need to set the `PROWLER_DB_CACHE_SIZE` environment variable.

For example:

```bash
> export PROWLER_DB_CACHE_SIZE=1000
```

The cache size is amount of memory in KiB that will be used. The default value is 2000 KiB.

> What's the SQLite cache size? The cache size refers to the amount of memory allocated for storing database pages in memory, which is used to reduce the need to read from the disk. The cache size can be configured using the PRAGMA cache_size command.

## Performance

Although the performance is not the same that the original Python data structure, it is fast enough to be used.

Have in count that Prowler is not a real-time application, so the performance is not the most important thing.

After some tests, the performance is similar to the original Python data structure.
