# FtraceParser

`ftraceparser` is a python package that convert Linux kernel ftrace report to a human readable format.

## Install

The package can be installed through pip (**recommended**)

`pip3 install ftraceparser`

You can also download the latest release from Github

## Introduction

Ftrace is a kernel trace tool on Linux kernel, it's wildly used for kernel debugging. 

The existed ftrace parsers like  `KernelShark` are powerful but lack of customization for daily debugging use (e.g., match each function entry to function exit), and most important, they do not provide a programming interface in terms of extensibility.

`ftraceparser` manages to provide a user-friendly python interface for parsing ftrace reports. It takes `trace-cmd` report as the input, and produce a easily-use internal console for inspection.

## Usage

There are some important features that `ftraceparser` provided.

### Convert to trace-cmd report

This step convert `trace-cmd.dat` to `trace.report`.

For more information, visit https://www.trace-cmd.org/

```
trace-cmd report > trace.report
```



### Open a ftrace report

```
python3 ftraceparser ./trace.report
```

###  

### List all entry functions

```
ftrace-parser> entry
```

![1](./resources/1.png)



### Find functions

```
ftrace-parser> find [FUNCTION_NAME]
```

![1](.\resources\2.png)

To find all occurrences, use `findall`

![1](.\resources\10.png)



### Show the caller of a function

```
ftrace-parser> caller [ID]
```

![1](.\resources\11.png)



### Show the callees of a function

```
ftrace-parser> callee [ID]
```

![1](.\resources\12.png)



### Find the entry function of a function

Find the entry function of this `seq_read()` which has the id of 24

```
ftrace-parser> entry [ID]
```

![1](.\resources\3.png)



### Print N nodes from somewhere

`pdn` will print `N` nodes from node `ID`, `LEVEL` controls how many levels of callee you want enter.

```
ftrace-parser> pdn[N] [ID]/[LEVEL]
```

For example, to print 10 nodes from node 24 with entering only level 1 callee

![1](.\resources\4.png)



If we enter level 3 callee, we will get more details.

![1](.\resources\5.png)



### Print the entire function

`pdf` prints the entire function `ID` with `LEVEL` callee

```
ftrace-parser> pdf [ID]/[LEVEL]
```

![1](.\resources\6.png)



### Block some functions

Sometimes, we don't want to show every function. To block a function from showing, use `block` command.

```
ftrace-parser> block [FUNCTION_NAME]
```

![1](.\resources\7.png)



### Delete block functions

To delete just one block function, use `delete` command following with the function name you want to delete.

```
ftrace-parser> delete [FUNCTION_NAME]
```

To delete all functions that have been blocked, just use `delete` followed by nothing

```
ftrace-parser> delete
```



### Filter

`ftraceparser` provide filter by task, pid, cpu, time stamp, event and entry

```
ftrace-parser> filter by [EXPR]
```

For example, we only want to show the trace of task `poc`

![1](.\resources\8.png)



Or we want to show the trace of pid between 1200 and 1220 

![1](.\resources\9.png)



### Remove filters

To remove some filter, use `filter-d` command and follow it with the filter

```
ftrace-parser> filter-d [task|pid|cpu|time_stamp|event|entry]
```

To remove them all, just use `filter-d`

```
ftrace-parser> filter-d
```

