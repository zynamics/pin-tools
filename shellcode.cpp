// Copyright 2010 zynamics GmbH
// Copyright 2011-2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "pin.H"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <set>
#include <list>
#include <sstream>

/**
* Specifies the maximum number of legit instructions the plugin keeps track of
* before control flow is transferred to the shellcode.
**/
const unsigned int MAX_LEGIT_INSTRUCTION_LOG_SIZE = 100;

/**
* Keeps track of legit instructions before control flow is transferred to she
* shellcode.
**/
std::list<std::string> legitInstructions;

/**
* Keeps track of disassembled instructions that were already dumped.
**/
std::set<std::string*> dumped;

/**
* Output file the shellcode information is dumped to.
**/
std::ofstream traceFile;

/**
* Command line option to specify the name of the output file.
* Default is shellcode.out.
**/
KNOB<string> outputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "shellcode.out", "specify trace file name");

/**
* Prints usage information.
**/
INT32 usage()
{
    cerr << "This tool produces a call trace." << endl << endl;
    cerr << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

/**
* Determines whether a given address belongs to a known module or not.
**/
bool isUnknownAddress(ADDRINT address)
{
	// An address belongs to a known module, if the address belongs to any
	// section of any module in the target address space.

	for(IMG img=APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img))
	{
		for(SEC sec=IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
		{
			if (address >= SEC_Address(sec) && address < SEC_Address(sec) + SEC_Size(sec))
			{
				return false;
			}
		}
	}

	return true;
}

/**
* Given a fully qualified path to a file, this function extracts the raw
* filename and gets rid of the path.
**/
std::string extractFilename(const std::string& filename)
{
	unsigned int lastBackslash = filename.rfind("\\");

	if (lastBackslash == -1)
	{
		return filename;
	}
	else
	{
		return filename.substr(lastBackslash + 1);
	}
}

/**
* Given an address, this function determines the name of the loaded module the
* address belongs to. If the address does not belong to any module, the empty
* string is returned.
**/
std::string getModule(ADDRINT address)
{
	// To find the module name of an address, iterate over all sections of all
	// modules until a section is found that contains the address.

	for(IMG img=APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img))
	{
		for(SEC sec=IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
		{
			if (address >= SEC_Address(sec) && address < SEC_Address(sec) + SEC_Size(sec))
			{
				return extractFilename(IMG_Name(img));
			}
		}
	}

	return "";
}

/**
* Converts a PIN instruction object into a disassembled string.
**/
std::string dumpInstruction(INS ins)
{
	std::stringstream ss;

	ADDRINT address = INS_Address(ins);

	// Generate address and module information
	ss << "0x" << setfill('0') << setw(8) << uppercase << hex << address << "::" << getModule(address) << "  ";

	// Generate instruction byte encoding
	for (int i=0;i<INS_Size(ins);i++)
	{
		ss << setfill('0') << setw(2) << (((unsigned int) *(unsigned char*)(address + i)) & 0xFF) << " ";
	}

	for (int i=INS_Size(ins);i<8;i++)
	{
		ss << "   ";
	}

	// Generate diassembled string
	ss << INS_Disassemble(ins);
	
	// Look up call information for direct calls
	if (INS_IsCall(ins) && INS_IsDirectBranchOrCall(ins))
	{
		ss << " -> " << RTN_FindNameByAddress(INS_DirectBranchOrCallTargetAddress(ins));
	}

	return ss.str();
}

/**
* Callback function that is executed every time an instruction identified as
* potential shellcode is executed.
**/
void dump_shellcode(std::string* instructionString)
{
	if (dumped.find(instructionString) != dumped.end())
	{
		// This check makes sure that an instruction is not dumped twice.
		// For a complete run trace it would make sense to dump an instruction
		// every time it is executed. However, imagine the shellcode has a
		// tight loop that is executed a million times. The resulting log file
		// is much easier to read if every instruction is only dumped once.

		return;
	}

	if (!legitInstructions.empty())
	{
		// If legit instructions have been logged before the shellcode is
		// executed, it is now a good time to dump them to the file. This
		// information then shows when control flow was transferred from
		// legit code to shellcode.

		traceFile << "Executed before" << endl;

		for (std::list<std::string>::iterator Iter = legitInstructions.begin(); Iter != legitInstructions.end(); ++Iter)
		{
			traceFile << *Iter << endl;
		}

		traceFile << endl << "Shellcode:" << endl;

		legitInstructions.clear();
	}

	traceFile << *instructionString << std::endl;

	dumped.insert(instructionString);
}

/**
* This function is called
**/
void traceInst(INS ins, VOID*)
{
	ADDRINT address = INS_Address(ins);

	if (isUnknownAddress(address))
	{
		// The address is an address that does not belong to any loaded module.
		// This is potential shellcode. For these instructions a callback
		// function is inserted that dumps information to the trace file when
		// the instruction is actually executed.

		INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(dump_shellcode),
			IARG_PTR, new std::string(dumpInstruction(ins)), IARG_END
		);
	}
	else
	{
		// The address is a legit address, meaning it is probably not part of
		// any shellcode. In this case we just log the instruction to dump it
		// later to show when control flow was transfered from legit code to
		// shellcode.

		legitInstructions.push_back(dumpInstruction(ins));

		if (legitInstructions.size() > MAX_LEGIT_INSTRUCTION_LOG_SIZE)
		{
			// Log only up to MAX_LEGIT_INSTRUCTION_LOG_SIZE instructions or the whole
			// program before the shellcode will be dumped.

			legitInstructions.pop_front();
		}
	}
}

/**
* Finalizer function that is called at the end of the trace process.
* In this script, the finalizer function is responsible for closing
* the shellcode output file.
**/
VOID fini(INT32, VOID*)
{
    traceFile.close();
}

int main(int argc, char *argv[])
{
    PIN_InitSymbols();

    if( PIN_Init(argc, argv))
    {
        return usage();
    }

    traceFile.open(outputFile.Value().c_str());

    string trace_header = string("#\n"
                                 "# Shellcode detector\n"
                                 "#\n");
    

    traceFile.write(trace_header.c_str(), trace_header.size());
    
    INS_AddInstrumentFunction(traceInst, 0);
    PIN_AddFiniFunction(fini, 0);

    // Never returns
    PIN_StartProgram();
    
    return 0;
}
