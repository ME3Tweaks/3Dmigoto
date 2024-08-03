// cmd_Decompiler.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include <iostream>     // console output

#include <D3Dcompiler.h>
#include "DecompileHLSL.h"
#include "version.h"
#include "log.h"
#define MIGOTO_DX 11 // Selects the DX11 disassembler in util.h - the DX9 dis/assembler is not very
                     // interesting since it is just Microsoft's - we can add it later, but low priority.
                     // The DX9 decompiler is more interesting, which is unrelated to this flag.
#include "util.h"
#include "shader.h"

using namespace std;

FILE *LogFile = stderr; // Log to stderr by default
bool gLogDebug = false;

static struct {
	std::vector<std::string> files;
	bool decompile;
	bool compile;
	bool disassemble_ms;
	bool disassemble_flugan;
	int disassemble_hexdump;
	bool disassemble_46;
	bool patch_cb_offsets;
	std::string reflection_reference;
	bool assemble;
	bool force;
	bool validate;
	bool lenient;
	bool stop;
} args;


// Old version directly using D3DDisassemble, suffers from precision issues due
// to bug in MS's disassembler that always prints floats with %f, which does
// not have sufficient precision to reproduce a 32bit floating point value
// exactly. Might still be useful for comparison:
static HRESULT DisassembleMS(const void *pShaderBytecode, size_t BytecodeLength, string *asmText)
{
	ID3DBlob *disassembly = nullptr;
	UINT flags = D3D_DISASM_ENABLE_DEFAULT_VALUE_PRINTS;
	string comments = "//   using 3Dmigoto command line v" + string(VER_FILE_VERSION_STR) + " on " + LogTime() + "//\n";

	HRESULT hr = D3DDisassemble(pShaderBytecode, BytecodeLength, flags, comments.c_str(), &disassembly);
	if (FAILED(hr)) {
		LogInfo("  disassembly failed. Error: %x\n", hr);
		return hr;
	}

	// Successfully disassembled into a Blob.  Let's turn it into a C++ std::string
	// so that we don't have a null byte as a terminator.  If written to a file,
	// the null bytes otherwise cause Git diffs to fail.
	*asmText = string(static_cast<char*>(disassembly->GetBufferPointer()));

	disassembly->Release();
	return S_OK;
}


static int validate_section(char section[4], unsigned char *old_section, unsigned char *new_section, size_t size, struct dxbc_header *old_dxbc)
{
	unsigned char *p1 = old_section, *p2 = new_section;
	int rc = 0;
	size_t pos;
	size_t off = (size_t)(old_section - (unsigned char*)old_dxbc);

	for (pos = 0; pos < size; pos++, p1++, p2++) {
		if (*p1 == *p2)
			continue;

		if (!rc)
			LogInfo("\n*** Assembly verification pass failed: mismatch in section %.4s:\n", section);
		LogInfo("  %.4s+0x%04Ix (0x%08Ix): expected 0x%02x, found 0x%02x\n",
				section, pos, off+pos, *p1, *p2);
		rc = 1;
	}

	return rc;
}



static HRESULT Decompile(const void* pShaderBytecode, size_t BytecodeLength, string* hlslText, string* shaderModel, bool includeCreatedBy)
{
	// Set all to zero, so we only init the ones we are using here:
	ParseParameters p = {0};
	DecompilerSettings d;
	bool patched = false;
	bool errorOccurred = false;
	string disassembly;
	HRESULT hret;

	hret = DisassembleMS(pShaderBytecode, BytecodeLength, &disassembly);
	if (FAILED(hret))
		return E_FAIL;

	LogInfo("    creating HLSL representation\n");

	p.bytecode = pShaderBytecode;
	p.decompiled = disassembly.c_str(); // XXX: Why do we call this "decompiled" when it's actually disassembled?
	p.decompiledSize = disassembly.size();
	p.G = &d;

	// Disable IniParams and StereoParams registers. This avoids inserting
	// these in a shader that already has them, such as some of our test
	// cases. Also, while cmd_Decompiler is part of 3DMigoto, it is NOT
	// 3DMigoto so it doesn't really make sense that it should add 3DMigoto
	// registers, and if someone wants these registers there is nothing
	// stopping them from adding them by hand. May break scripts that use
	// cmd_Decompiler and expect these to be here, but those scripts can be
	// updated to add them or they can keep using an old version.
	d.IniParamsReg = -1;
	d.StereoParamsReg = -1;

	*hlslText = DecompileBinaryHLSL(p, patched, *shaderModel, errorOccurred, includeCreatedBy);
	if (!hlslText->size() || errorOccurred) {
		LogInfo("    error while decompiling\n");
		return E_FAIL;
	}

	return S_OK;
}
extern "C"
{
	__declspec(dllexport) int __stdcall DecompileShader(const unsigned char* shaderBytecode, unsigned int bytecodeSize, const char* outStr, int buffSize, BOOL includeCreatedBy)
	{
		HRESULT hret;
		string output;
		string model;

		hret = Decompile(shaderBytecode, bytecodeSize, &output, &model, includeCreatedBy);
		if (FAILED(hret))
			output = "Decompilation failed";

		if (output.size() > buffSize)
		{
			return -1;
		}

		memcpy((void*)outStr, output.c_str(), output.length());
		return output.length();
	}
}

