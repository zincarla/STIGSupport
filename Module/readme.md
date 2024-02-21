# StigCKLBSupport.psm1

This is the core module for this entire project. It provides the necessary functions to read and write CKLB files. This module can assist in automating checks, running metrics on CKLB files and merging checks from different CKLB files into one. 

# StigXCCDFSupport.psm1

This is a secondary module that allows pulling some data from an XCCDF file as returned by a SCC scan. It also extends the StigCKLBSupport.psm1 by providing a couple functions to answer pre-created CKLB files with answers from an XCCDF file.