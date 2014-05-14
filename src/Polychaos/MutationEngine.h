#pragma once

#include "MutationImpl.h"
#include "LDasm.h"

namespace mut
{

class MutationEngine
{
public:
    /// <summary>
    /// MutationEngine ctor
    /// </summary>
    /// <param name="pImpl">Code mutator inplementation</param>
    MutationEngine( MutationImpl* pImpl );

    ~MutationEngine();

    /// <summary>
    /// Mutate provided code
    /// Every single byte inside buffer is treated as code. 
    /// So any data mixed with code will corrupt code graph
    /// </summary>
    /// <param name="ptr">Code ptr.</param>
    /// <param name="size">Code size</param>
    /// <param name="rva_ep">Entry point relative to Code ptr</param>
    /// <param name="extDelta">New code section RVA - old code section RVA</param>
    /// <param name="extBase">Image base + code section RVA</param>
    /// <param name="obuf">Output buffer</param>
    /// <returns>Output buffer size</returns>
    size_t Mutate( uint8_t* ptr, size_t size, 
                   size_t& rva_ep, size_t extDelta,
                   size_t extBase, uint8_t*& obuf );

    /// <summary>
    /// Get instruction data by RVA; relative to code base
    /// </summary>
    /// <param name="rva">Instruction RVA</param>
    /// <returns>Instruction data, if any</returns>
    InstructionData* GetIdataByRVA( uint32_t rva );

private:
    /// <summary>
    /// Disassemble code
    /// </summary>
    /// <param name="extBase">Image base + code section RVA</param>
    void Disasm( size_t extBase );

    /// <summary>
    /// Process code graph
    /// Link relative jumps and remove short jumps
    /// </summary>
    /// <returns>0 if success, non 0 if error</returns>
    size_t Process();
    void AssembleAndLink( size_t &rva_ep, size_t extDelta, size_t extBase );

    /// <summary>
    /// Reset internal buffers
    /// </summary>
    void Reset();

private:
    uint8_t* _ptr  = nullptr;
    uint8_t* _ibuf = nullptr;   // Input code
    uint8_t* _obuf = nullptr;   // Output buffer
    uint8_t* _imap = nullptr;   // Input code map
    uint8_t* _omap = nullptr;   // Output code map
    uint32_t _size = 0;         // Input code size
    uint32_t _osize = 0;        // Output buffer size

    InstructionData* _root = nullptr;       // Graph root
    MutationImpl* _pImpl = nullptr;         // Code mutation implementation
};

}