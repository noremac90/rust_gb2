use std::{hash::Hasher, cell::RefCell, rc::Rc};

pub struct Registers {
    pub a: u8,
    pub f: u8,
    pub b: u8,
    pub c: u8,
    pub d: u8,
    pub e: u8,
    pub h: u8,
    pub l: u8,
    pub pc: u16,
    pub sp: u16
}

impl Registers {

    pub const Z_FLAG_MASK: u8 = 0b10000000;
    pub const N_FLAG_MASK: u8 = 0b01000000;
    pub const H_FLAG_MASK: u8 = 0b00100000;
    pub const C_FLAG_MASK: u8 = 0b00010000;

    pub fn new() -> Self {
        Registers {
            a: 0x00,
            f: 0xB0, 
            b: 0x00,
            c: 0x00,
            d: 0x00,
            e: 0x00,
            h: 0x00,
            l: 0x00,
            pc: 0x0000,
            sp: 0xFFFE
        }
    }

    pub fn hl(&self) -> u16 {
        u16::from_be_bytes([self.h, self.l])
    }

    pub fn af(&self) -> u16 {
        u16::from_be_bytes([self.a, self.f])
    }

    pub fn bc(&self) -> u16 {
        u16::from_be_bytes([self.b, self.c])
    }

    pub fn de(&self) -> u16 {
        u16::from_be_bytes([self.d, self.e])
    }

    pub fn set_hl(&mut self, value: u16) {
        self.h = u16::to_be_bytes(value)[0];
        self.l = u16::to_be_bytes(value)[1];
    }

    pub fn set_af(&mut self, value: u16) {
        self.a = u16::to_be_bytes(value)[0];
        self.f = u16::to_be_bytes(value)[1];
    }

    pub fn set_bc(&mut self, value: u16) {
        self.b = u16::to_be_bytes(value)[0];
        self.c = u16::to_be_bytes(value)[1];
    }

    pub fn set_de(&mut self, value: u16) {
        self.d = u16::to_be_bytes(value)[0];
        self.e = u16::to_be_bytes(value)[1];
    }

    pub fn z(&self) -> bool {
        (self.f & Self::Z_FLAG_MASK) != 0
    }

    pub fn h(&self) -> bool {
        (self.f & Self::H_FLAG_MASK) != 0
    }

    pub fn c(&self) -> bool {
        (self.f & Self::C_FLAG_MASK) != 0
    }

    pub fn n(&self) -> bool {
        (self.f & Self::N_FLAG_MASK) != 0
    }

    pub fn set_z(&mut self, value: bool) {
        if value {
            self.f |= Self::Z_FLAG_MASK;
        } else {
            self.f &= !Self::Z_FLAG_MASK;
        }
    }

    pub fn set_h(&mut self, value: bool) {
        if value {
            self.f |= Self::H_FLAG_MASK;
        } else {
            self.f &= !Self::H_FLAG_MASK;
        }
    }

    pub fn set_n(&mut self, value: bool) {
        if value {
            self.f |= Self::N_FLAG_MASK;
        } else {
            self.f &= !Self::N_FLAG_MASK;
        }
    }

    pub fn set_c(&mut self, value: bool) {
        if value {
            self.f |= Self::C_FLAG_MASK;
        } else {
            self.f &= !Self::C_FLAG_MASK;
        }
    }
}

pub struct CPU {
    reg: Registers,
    cycles: u64,
    mmu: MMU,
    gpu: GPU
}

impl CPU{
    pub fn new(mmu: MMU) -> Self {
        Self {
            reg: Registers::new(),
            cycles: 0,
            mmu: mmu,
            gpu: GPU::new()
        }
    }

    fn load(&mut self, file: &'static str) {
        let bytes =std::fs::read(file).unwrap();

        for (i, v) in bytes.iter().enumerate() {
            self.mmu.ROM0[i] = *v;
        }

        self.reg.pc = 0;
    }

    fn clock(&mut self) {
        self.cycles += 4;
        self.gpu.tick(&mut self.mmu, 4);
    }

    pub fn read_addr(&mut self, addr: u16) -> u8 {
        self.clock();
        self.mmu.read(addr)
    }

    pub fn write_addr(&mut self, addr: u16, value: u8) {
        self.clock();
        if(addr > 0x8000 && addr < 0x9FFF) {
            println!("Writing {:02X} to VRAM {:04X} from {:04x}", value, addr, self.reg.pc);
        }
        self.mmu.write(addr, value);
    }

    pub fn read_addr16(&mut self, addr: u16) -> u16 {
        u16::from_le_bytes([self.read_addr(addr), self.read_addr(addr + 1)])
    }

    pub fn write_addr16(&mut self, addr: u16, value: u16) {
        self.write_addr(addr, u16::to_le_bytes(value)[0]);
        self.write_addr(addr + 1, u16::to_le_bytes(value)[1])
    }

    pub fn fetch8(&mut self) -> u8 {
        let val = self.read_addr(self.reg.pc);
        self.reg.pc += 1;

        val
    }

    pub fn fetch16(&mut self) -> u16 {
        u16::from_le_bytes([self.fetch8(), self.fetch8()])
    }

    pub fn step(&mut self) {
        let ins = self.fetch8();

        match ins {
            0x00 => { } // NOP
            0x01 => { let value = self.fetch16(); self.reg.set_bc(value) }
            0x02 => { self.write_addr(self.reg.bc(), self.reg.a ) }
            0x03 => { let result = self.x16_alu_inc(self.reg.bc()); self.reg.set_bc(result); }
            0x04 => { self.reg.b = self.x8_alu_inc(self.reg.b) }
            0x05 => { self.reg.b = self.x8_alu_dec(self.reg.b) }
            0x06 => { self.reg.b = self.fetch8() }
            0x07 => { self.reg.a = self.x8_rlca() }
            0x08 => { let addr = self.fetch16(); self.write_addr16(addr, self.reg.sp) }
            0x09 => { let result = self.x16_alu_add(self.reg.hl(), self.reg.bc()); self.reg.set_hl(result) }
            0x0A => { self.reg.a = self.read_addr(self.reg.bc()) }
            0x0B => { let result = self.x16_alu_dec(self.reg.bc()); self.reg.set_bc(result) }
            0x0C => { self.reg.c = self.x8_alu_inc(self.reg.c) }
            0x0D => { self.reg.c = self.x8_alu_dec(self.reg.c) }
            0x0E => { self.reg.c = self.fetch8() }
            0x0F => { self.reg.a = self.x8_rrca() }

            0x10 => { unimplemented!() }
            0x11 => { let value = self.fetch16(); self.reg.set_de(value) }
            0x12 => { self.write_addr(self.reg.de(), self.reg.a ) }
            0x13 => { let result = self.x16_alu_inc(self.reg.de()); self.reg.set_de(result); }
            0x14 => { self.reg.d = self.x8_alu_inc(self.reg.d) }
            0x15 => { self.reg.d = self.x8_alu_dec(self.reg.d) }
            0x16 => { self.reg.d = self.fetch8() }
            0x17 => { self.reg.a = self.x8_rla() }
            0x18 => { let offset = self.fetch8() as i8; self.op_jr(offset) }
            0x19 => { let result = self.x16_alu_add(self.reg.hl(), self.reg.de()); self.reg.set_hl(result) }
            0x1A => { self.reg.a = self.read_addr(self.reg.de()) }
            0x1B => { let result = self.x16_alu_dec(self.reg.de()); self.reg.set_de(result) }
            0x1C => { self.reg.e = self.x8_alu_inc(self.reg.e) }
            0x1D => { self.reg.e = self.x8_alu_dec(self.reg.e) }
            0x1E => { self.reg.e = self.fetch8() }
            0x1F => { self.reg.a = self.x8_rra() }

            0x20 => { let offset = self.fetch8() as i8; self.op_jrc(offset, None, Some(false)) }
            0x21 => { let value = self.fetch16(); self.reg.set_hl(value) }
            0x22 => { self.write_addr(self.reg.hl(), self.reg.a); self.reg.set_hl(self.reg.hl().wrapping_add(1)) }
            0x23 => { let result = self.x16_alu_inc(self.reg.hl()); self.reg.set_hl(result); }
            0x24 => { self.reg.h = self.x8_alu_inc(self.reg.h) }
            0x25 => { self.reg.h = self.x8_alu_dec(self.reg.h) }
            0x26 => { self.reg.h = self.fetch8() }
            0x27 => { unimplemented!() }
            0x28 => { let offset = self.fetch8() as i8; self.op_jrc(offset, None, Some(true)) }
            0x29 => { let result = self.x16_alu_add(self.reg.hl(), self.reg.hl()); self.reg.set_hl(result) }
            0x2A => { self.reg.a = self.read_addr(self.reg.hl()); self.reg.set_hl(self.reg.hl().wrapping_add(1)) }
            0x2B => { let result = self.x16_alu_dec(self.reg.hl()); self.reg.set_hl(result) }
            0x2C => { self.reg.l = self.x8_alu_inc(self.reg.l) }
            0x2D => { self.reg.l = self.x8_alu_dec(self.reg.l) }
            0x2E => { self.reg.l = self.fetch8() }
            0x2F => { self.op_cpl() }

            0x30 => { let offset = self.fetch8() as i8; self.op_jrc(offset, Some(false), None) }
            0x31 => { self.reg.sp = self.fetch16() }
            0x32 => { self.write_addr(self.reg.hl(), self.reg.a); self.reg.set_hl(self.reg.hl().wrapping_sub(1)) }
            0x33 => { self.reg.sp = self.x16_alu_inc(self.reg.sp) }
            0x34 => {
                let mut value = self.read_addr(self.reg.hl());
                value = self.x8_alu_inc(value);
                self.write_addr(self.reg.hl(), value);
            }
            0x35 => {
                let mut value = self.read_addr(self.reg.hl());
                value = self.x8_alu_dec(value);
                self.write_addr(self.reg.hl(), value);
            }
            0x36 => { let imm = self.fetch8(); self.write_addr(self.reg.hl(), imm) }
            0x37 => { self.op_scf() }
            0x38 => { let offset = self.fetch8() as i8; self.op_jrc(offset, Some(true), None) }
            0x39 => { let result = self.x16_alu_add(self.reg.hl(), self.reg.sp); self.reg.set_hl(result) }
            0x3A => { self.reg.a = self.read_addr(self.reg.hl()); self.reg.set_hl(self.reg.hl().wrapping_sub(1)) }
            0x3B => { self.reg.sp = self.x16_alu_dec(self.reg.sp) }
            0x3C => { self.reg.a = self.x8_alu_inc(self.reg.a) }
            0x3D => { self.reg.a = self.x8_alu_dec(self.reg.a) }
            0x3E => { self.reg.a = self.fetch8() }
            0x3F => { self.op_ccf() }

            0x40 => { self.reg.b = self.reg.b }
            0x41 => { self.reg.b = self.reg.c }
            0x42 => { self.reg.b = self.reg.d }
            0x43 => { self.reg.b = self.reg.e }
            0x44 => { self.reg.b = self.reg.h }
            0x45 => { self.reg.b = self.reg.l }
            0x46 => { self.reg.b = self.read_addr(self.reg.hl()) }
            0x47 => { self.reg.b = self.reg.a }
            0x48 => { self.reg.c = self.reg.b }
            0x49 => { self.reg.c = self.reg.c }
            0x4A => { self.reg.c = self.reg.d }
            0x4B => { self.reg.c = self.reg.e }
            0x4C => { self.reg.c = self.reg.h }
            0x4D => { self.reg.c = self.reg.l }
            0x4E => { self.reg.c = self.read_addr(self.reg.hl()) }
            0x4F => { self.reg.c = self.reg.a }

            0x50 => { self.reg.d = self.reg.b }
            0x51 => { self.reg.d = self.reg.c }
            0x52 => { self.reg.d = self.reg.d }
            0x53 => { self.reg.d = self.reg.e }
            0x54 => { self.reg.d = self.reg.h }
            0x55 => { self.reg.d = self.reg.l }
            0x56 => { self.reg.d = self.read_addr(self.reg.hl()) }
            0x57 => { self.reg.d = self.reg.a }
            0x58 => { self.reg.e = self.reg.b }
            0x59 => { self.reg.e = self.reg.c }
            0x5A => { self.reg.e = self.reg.d }
            0x5B => { self.reg.e = self.reg.e }
            0x5C => { self.reg.e = self.reg.h }
            0x5D => { self.reg.e = self.reg.l }
            0x5E => { self.reg.e = self.read_addr(self.reg.hl()) }
            0x5F => { self.reg.e = self.reg.a }

            0x60 => { self.reg.h = self.reg.b }
            0x61 => { self.reg.h = self.reg.c }
            0x62 => { self.reg.h = self.reg.d }
            0x63 => { self.reg.h = self.reg.e }
            0x64 => { self.reg.h = self.reg.h }
            0x65 => { self.reg.h = self.reg.l }
            0x66 => { self.reg.h = self.read_addr(self.reg.hl()) }
            0x67 => { self.reg.h = self.reg.a }
            0x68 => { self.reg.l = self.reg.b }
            0x69 => { self.reg.l = self.reg.c }
            0x6A => { self.reg.l = self.reg.d }
            0x6B => { self.reg.l = self.reg.e }
            0x6C => { self.reg.l = self.reg.h }
            0x6D => { self.reg.l = self.reg.l }
            0x6E => { self.reg.l = self.read_addr(self.reg.hl()) }
            0x6F => { self.reg.l = self.reg.a }

            0x70 => { self.write_addr(self.reg.hl(), self.reg.b) }
            0x71 => { self.write_addr(self.reg.hl(), self.reg.c) }
            0x72 => { self.write_addr(self.reg.hl(), self.reg.d) }
            0x73 => { self.write_addr(self.reg.hl(), self.reg.e) }
            0x74 => { self.write_addr(self.reg.hl(), self.reg.h) }
            0x75 => { self.write_addr(self.reg.hl(), self.reg.l) }
            0x76 => { unimplemented!() }
            0x77 => { self.write_addr(self.reg.hl(), self.reg.a) }
            0x78 => { self.reg.a = self.reg.b }
            0x79 => { self.reg.a = self.reg.c }
            0x7A => { self.reg.a = self.reg.d }
            0x7B => { self.reg.a = self.reg.e }
            0x7C => { self.reg.a = self.reg.h }
            0x7D => { self.reg.a = self.reg.l }
            0x7E => { self.reg.a = self.read_addr(self.reg.hl()) }
            0x7F => { self.reg.a = self.reg.a }

            0x80 => { self.reg.a = self.x8_alu_add(self.reg.a, self.reg.b) }
            0x81 => { self.reg.a = self.x8_alu_add(self.reg.a, self.reg.c) }
            0x82 => { self.reg.a = self.x8_alu_add(self.reg.a, self.reg.d) }
            0x83 => { self.reg.a = self.x8_alu_add(self.reg.a, self.reg.e) }
            0x84 => { self.reg.a = self.x8_alu_add(self.reg.a, self.reg.h) }
            0x85 => { self.reg.a = self.x8_alu_add(self.reg.a, self.reg.l) }
            0x86 => { let rhs = self.read_addr(self.reg.hl()); self.reg.a = self.x8_alu_add(self.reg.a, rhs) }
            0x87 => { self.reg.a = self.x8_alu_add(self.reg.a, self.reg.a) }
            0x88 => { self.reg.a = self.x8_alu_adc(self.reg.a, self.reg.b) }
            0x89 => { self.reg.a = self.x8_alu_adc(self.reg.a, self.reg.c) }
            0x8A => { self.reg.a = self.x8_alu_adc(self.reg.a, self.reg.d) }
            0x8B => { self.reg.a = self.x8_alu_adc(self.reg.a, self.reg.e) }
            0x8C => { self.reg.a = self.x8_alu_adc(self.reg.a, self.reg.h) }
            0x8D => { self.reg.a = self.x8_alu_adc(self.reg.a, self.reg.l) }
            0x8E => { let rhs = self.read_addr(self.reg.hl()); self.reg.a = self.x8_alu_adc(self.reg.a, rhs) }
            0x8F => { self.reg.a = self.x8_alu_adc(self.reg.a, self.reg.a) }

            0x90 => { self.reg.a = self.x8_alu_sub(self.reg.a, self.reg.b) }
            0x91 => { self.reg.a = self.x8_alu_sub(self.reg.a, self.reg.c) }
            0x92 => { self.reg.a = self.x8_alu_sub(self.reg.a, self.reg.d) }
            0x93 => { self.reg.a = self.x8_alu_sub(self.reg.a, self.reg.e) }
            0x94 => { self.reg.a = self.x8_alu_sub(self.reg.a, self.reg.h) }
            0x95 => { self.reg.a = self.x8_alu_sub(self.reg.a, self.reg.l) }
            0x96 => { let rhs = self.read_addr(self.reg.hl()); self.reg.a = self.x8_alu_sub(self.reg.a, rhs) }
            0x97 => { self.reg.a = self.x8_alu_sub(self.reg.a, self.reg.a) }
            0x98 => { self.reg.a = self.x8_alu_sbc(self.reg.a, self.reg.b) }
            0x99 => { self.reg.a = self.x8_alu_sbc(self.reg.a, self.reg.c) }
            0x9A => { self.reg.a = self.x8_alu_sbc(self.reg.a, self.reg.d) }
            0x9B => { self.reg.a = self.x8_alu_sbc(self.reg.a, self.reg.e) }
            0x9C => { self.reg.a = self.x8_alu_sbc(self.reg.a, self.reg.h) }
            0x9D => { self.reg.a = self.x8_alu_sbc(self.reg.a, self.reg.l) }
            0x9E => { let rhs = self.read_addr(self.reg.hl()); self.reg.a = self.x8_alu_sbc(self.reg.a, rhs) }
            0x9F => { self.reg.a = self.x8_alu_sbc(self.reg.a, self.reg.a) }

            0xA0 => { self.reg.a = self.x8_alu_and(self.reg.a, self.reg.b) }
            0xA1 => { self.reg.a = self.x8_alu_and(self.reg.a, self.reg.c) }
            0xA2 => { self.reg.a = self.x8_alu_and(self.reg.a, self.reg.d) }
            0xA3 => { self.reg.a = self.x8_alu_and(self.reg.a, self.reg.e) }
            0xA4 => { self.reg.a = self.x8_alu_and(self.reg.a, self.reg.h) }
            0xA5 => { self.reg.a = self.x8_alu_and(self.reg.a, self.reg.l) }
            0xA6 => { let rhs = self.read_addr(self.reg.hl()); self.reg.a = self.x8_alu_and(self.reg.a, rhs) }
            0xA7 => { self.reg.a = self.x8_alu_and(self.reg.a, self.reg.a) }
            0xA8 => { self.reg.a = self.x8_alu_xor(self.reg.a, self.reg.b) }
            0xA9 => { self.reg.a = self.x8_alu_xor(self.reg.a, self.reg.c) }
            0xAA => { self.reg.a = self.x8_alu_xor(self.reg.a, self.reg.d) }
            0xAB => { self.reg.a = self.x8_alu_xor(self.reg.a, self.reg.e) }
            0xAC => { self.reg.a = self.x8_alu_xor(self.reg.a, self.reg.h) }
            0xAD => { self.reg.a = self.x8_alu_xor(self.reg.a, self.reg.l) }
            0xAE => { let rhs = self.read_addr(self.reg.hl()); self.reg.a = self.x8_alu_xor(self.reg.a, rhs) }
            0xAF => { self.reg.a = self.x8_alu_xor(self.reg.a, self.reg.a) }

            0xB0 => { self.reg.a = self.x8_alu_or(self.reg.a, self.reg.b) }
            0xB1 => { self.reg.a = self.x8_alu_or(self.reg.a, self.reg.c) }
            0xB2 => { self.reg.a = self.x8_alu_or(self.reg.a, self.reg.d) }
            0xB3 => { self.reg.a = self.x8_alu_or(self.reg.a, self.reg.e) }
            0xB4 => { self.reg.a = self.x8_alu_or(self.reg.a, self.reg.h) }
            0xB5 => { self.reg.a = self.x8_alu_or(self.reg.a, self.reg.l) }
            0xB6 => { let rhs = self.read_addr(self.reg.hl()); self.reg.a = self.x8_alu_or(self.reg.a, rhs) }
            0xB7 => { self.reg.a = self.x8_alu_or(self.reg.a, self.reg.a) }
            0xB8 => { self.x8_alu_cp(self.reg.a, self.reg.b) }
            0xB9 => { self.x8_alu_cp(self.reg.a, self.reg.c) }
            0xBA => { self.x8_alu_cp(self.reg.a, self.reg.d) }
            0xBB => { self.x8_alu_cp(self.reg.a, self.reg.e) }
            0xBC => { self.x8_alu_cp(self.reg.a, self.reg.h) }
            0xBD => { self.x8_alu_cp(self.reg.a, self.reg.l) }
            0xBE => { let rhs = self.read_addr(self.reg.hl()); self.x8_alu_cp(self.reg.a, rhs) }
            0xBF => { self.x8_alu_cp(self.reg.a, self.reg.a) }

            0xC0 => { self.op_retc(None, Some(false)) }
            0xC1 => { let value = self.pop(); self.reg.set_bc(value) }
            0xC2 => { let addr = self.fetch16(); self.op_jmpc(addr, None, Some(false)) }
            0xC3 => { let addr = self.fetch16(); self.op_jmp(addr) }
            0xC4 => { let addr = self.fetch16(); self.op_callc(addr, None, Some(false)) }
            0xC5 => { self.clock(); self.push(self.reg.bc()) } // Extra clock here?
            0xC6 => { let rhs = self.fetch8(); self.reg.a = self.x8_alu_add(self.reg.a, rhs) }
            0xC7 => { unimplemented!() }
            0xC8 => { self.op_retc(None, Some(false)) }
            0xC9 => { self.op_ret() }
            0xCA => { let addr = self.fetch16(); self.op_jmpc(addr, None, Some(true)) }
            0xCB => { self.execute_cb() }
            0xCC => { let addr = self.fetch16(); self.op_callc(addr, None, Some(true)) }
            0xCD => { let addr = self.fetch16(); self.op_call(addr) }
            0xCE => { let rhs = self.fetch8(); self.reg.a = self.x8_alu_adc(self.reg.a, rhs) }

            0xD0 => { self.op_retc(Some(false), None) }
            0xD1 => { let value = self.pop(); self.reg.set_de(value) }
            0xD2 => { let addr = self.fetch16(); self.op_jmpc(addr, Some(false), None) }
            // 0xD3
            0xD4 => { let addr = self.fetch16(); self.op_callc(addr, Some(false), None) }
            0xD5 => { self.clock(); self.push(self.reg.de()) } // Extra clock here?
            0xD6 => { let rhs = self.fetch8(); self.reg.a = self.x8_alu_sub(self.reg.a, rhs) }
            0xD7 => { unimplemented!() }
            0xD8 => { self.op_retc(Some(true), None) }
            0xD9 => { unimplemented!() }
            0xDA => { let addr = self.fetch16(); self.op_jmpc(addr, Some(true), None) }
            // 0xDB
            0xDC => { let addr = self.fetch16(); self.op_callc(addr, Some(true), None) }
            // 0xDD
            0xDE => { let rhs = self.fetch8(); self.reg.a = self.x8_alu_sbc(self.reg.a, rhs) }
            0xDF => { unimplemented!() }

            0xE0 => { let offset = self.fetch8(); self.write_addr(0xFF00u16.wrapping_add(offset as u16), self.reg.a) }
            0xE1 => { let value = self.pop(); self.reg.set_hl(value) }
            0xE2 => { self.write_addr(0xFF00u16.wrapping_add(self.reg.c as u16), self.reg.a) }
            // 0xE3
            // 0xE4
            0xE5 => { self.clock(); self.push(self.reg.hl()) }
            0xE6 => { let rhs = self.fetch8(); self.reg.a = self.x8_alu_and(self.reg.a, rhs) }
            0xE7 => { unimplemented!() }
            0xE8 => { let value = self.fetch8() as i8; self.clock(); self.clock(); self.reg.sp = self.x16_alu_add(self.reg.sp, value as u16); self.reg.set_z(false) } // Need to reset zero flag here
            0xE9 => { self.op_jmphl() }
            0xEA => { let addr = self.fetch16(); self.write_addr(addr, self.reg.a); }//self.reg.a = self.read_addr(addr) }
            // 0xEB
            // 0xEC
            // 0xED
            0xEE => { let rhs = self.fetch8(); self.reg.a = self.x8_alu_xor(self.reg.a, rhs) }
            0xEF => { unimplemented!() }

            0xF0 => { let offset = self.fetch8(); self.reg.a = self.read_addr(0xFF00u16.wrapping_add(offset as u16)) }
            0xF1 => { let value = self.pop(); self.reg.set_af(value) }
            0xF2 => { self.reg.a = self.read_addr(0xFF00u16.wrapping_add(self.reg.c as u16)) }
            0xF3 => { unimplemented!() }
            // 0xF4
            0xF5 => {  self.clock(); self.push(self.reg.af()) }
            0xF6 => { let rhs = self.fetch8(); self.reg.a = self.x8_alu_or(self.reg.a, rhs) }
            0xF7 => { unimplemented!() }
            0xF8 => { let offset = self.fetch8() as i8; let result = self.x16_alu_add(self.reg.sp, offset as u16); self.reg.set_hl(result); self.clock() }
            0xF9 => { self.clock(); self.reg.sp = self.reg.hl() }
            0xFA => { let addr = self.fetch16(); self.reg.a = self.read_addr(addr) }
            0xFB => { unimplemented!() }
            //0xFC
            //0xFD
            0xFE => { let rhs = self.fetch8(); self.x8_alu_cp(self.reg.a, rhs) }
            0xFF => { unimplemented!() }

            _ => { }
        }

    }

    pub fn execute_cb(&mut self) {
        let ins = self.fetch8();

        let x = ins >> 6;
        let y = (ins & 0b0011_1000) >> 3;
        let z = ins & 0b0000_0111;

        let op: fn(&'_ mut CPU, u8) -> u8;


        if x == 0 {

            match y {
                0 => op = CPU::x8_rlc,
                1 => op = CPU::x8_rrc,
                2 => op = CPU::x8_rl,
                3 => op = CPU::x8_rr,
                _ => unreachable!()
            }

            match z {
                0 => self.reg.b = op(self, self.reg.b),
                1 => self.reg.c = op(self, self.reg.c),
                2 => self.reg.d = op(self, self.reg.d),
                3 => self.reg.e = op(self, self.reg.e),
                4 => self.reg.h = op(self, self.reg.h),
                5 => self.reg.l = op(self, self.reg.l),
                6 => { let mut value = self.read_addr(self.reg.hl()); value = op(self, value); self.write_addr(self.reg.hl(), value) }
                7 => self.reg.a = op(self, self.reg.a),
                _ => unreachable!()
            }


        } else if x == 1 {
            match z {
                0 => self.op_bit(self.reg.b, y),
                1 => self.op_bit(self.reg.c, y),
                2 => self.op_bit(self.reg.d, y),
                3 => self.op_bit(self.reg.e, y),
                4 => self.op_bit(self.reg.h, y),
                5 => self.op_bit(self.reg.l, y),
                6 => { let value = self.read_addr(self.reg.hl()); self.op_bit(value, y) },
                7 => self.op_bit(self.reg.a, y),

                _ => unreachable!()
            }
        } else if x == 2 {
            match z {
                0 => self.reg.b = self.op_reset(self.reg.b, y),
                1 => self.reg.c = self.op_reset(self.reg.c, y),
                2 => self.reg.d = self.op_reset(self.reg.d, y),
                3 => self.reg.e = self.op_reset(self.reg.e, y),
                4 => self.reg.h = self.op_reset(self.reg.h, y),
                5 => self.reg.l = self.op_reset(self.reg.l, y),
                6 => { let mut value = self.read_addr(self.reg.hl()); value = self.op_reset(value, y); self.write_addr(self.reg.hl(), value) },
                7 => self.reg.a = self.op_reset(self.reg.a, y),

                _ => unreachable!()
            }
        } else if x == 3 {
            match z {
                0 => self.reg.b = self.op_set(self.reg.b, y),
                1 => self.reg.c = self.op_set(self.reg.c, y),
                2 => self.reg.d = self.op_set(self.reg.d, y),
                3 => self.reg.e = self.op_set(self.reg.e, y),
                4 => self.reg.h = self.op_set(self.reg.h, y),
                5 => self.reg.l = self.op_set(self.reg.l, y),
                6 => { let mut value = self.read_addr(self.reg.hl()); value = self.op_set(value, y); self.write_addr(self.reg.hl(), value) },
                7 => self.reg.a = self.op_set(self.reg.a, y),

                _ => unreachable!()
            }
        }

    }

    pub fn op_bit(&mut self, value: u8, bit: u8) {
        self.reg.set_z(value & (1u8 << bit) == 0);
        self.reg.set_n(false);
        self.reg.set_h(true);
    }

    pub fn op_set(&mut self, value: u8, bit: u8) -> u8 {
        value | (1u8 << bit)
    }

    pub fn op_reset(&mut self, value: u8, bit: u8) -> u8 {
        value & !(1u8 << bit)
    }

    pub fn push(&mut self, value: u16) {
        self.write_addr16(self.reg.sp, value);
        self.reg.sp -= 2;
    }

    pub fn pop(&mut self) -> u16 {
        self.reg.sp += 2;
        let value = self.read_addr16(self.reg.sp);
        value
    }

    // 4 cycles fetch
    // 8 cycles fetch
    pub fn op_call(&mut self, addr: u16) {
        self.push(self.reg.pc); // 8 cycles

        // 4 extra cycles?
        self.clock();
        self.reg.pc = addr;
        
    }

    // 4 cycles fetch
    // 8 cycles fetch
    pub fn op_callc(&mut self, addr: u16, carry_cond: Option<bool>, zero_cond: Option<bool>) {
        
        assert!(carry_cond.is_some() != zero_cond.is_some());

        if let Some(flag) = carry_cond {
            if self.reg.c() == flag {
                self.push(self.reg.pc); // 8 cycles
                self.reg.pc = addr;
                self.clock(); // 4 cycles

                // 24 cycles
            }
        }

        if let Some(flag) = zero_cond {
            if self.reg.z() == flag {
                self.push(self.reg.pc);
                self.reg.pc = addr;
                self.clock()
            }
        }
        
    }

    pub fn op_ret(&mut self) {
        let addr = self.pop();
        self.clock();
        self.reg.pc = addr;
    }

    pub fn op_retc(&mut self, carry_cond: Option<bool>, zero_cond: Option<bool>) {
        
        assert!(carry_cond.is_some() != zero_cond.is_some());

        self.clock();

        if let Some(flag) = carry_cond {
            if self.reg.c() == flag {
                let addr = self.pop();
                self.reg.pc = addr;
                self.clock();
            }
        }

        if let Some(flag) = zero_cond {
            if self.reg.z() == flag {
                let addr = self.pop();
                self.reg.pc = addr;
                self.clock()
            }
        }
    }



    pub fn op_jr(&mut self, offset: i8) {
        self.reg.pc = self.reg.pc.wrapping_add(offset as u16);
        self.clock();
    }

    pub fn op_jrc(&mut self, offset: i8, carry_cond: Option<bool>, zero_cond: Option<bool>) {
        let addr = self.reg.pc.wrapping_add(offset as u16);

        assert!(carry_cond.is_some() != zero_cond.is_some());

        if let Some(flag) = carry_cond {
            if self.reg.c() == flag {
                self.reg.pc = addr;
                self.clock();
            }
        }

        if let Some(flag) = zero_cond {
            if self.reg.z() == flag {
                self.reg.pc = addr;
                self.clock()
            }
        }
    }

    pub fn op_jmp(&mut self, addr: u16) {
        self.reg.pc = addr;
        self.clock();
    }

    pub fn op_jmpc(&mut self, addr: u16, carry_cond: Option<bool>, zero_cond: Option<bool>) {

        assert!(carry_cond.is_some() != zero_cond.is_some());

        if let Some(flag) = carry_cond {
            if self.reg.c() == flag {
                self.reg.pc = addr;
                self.clock();
            }
        }

        if let Some(flag) = zero_cond {
            if self.reg.z() == flag {
                self.reg.pc = addr;
                self.clock()
            }
        }
    }

    pub fn op_jmphl(&mut self) {
        self.reg.pc = self.reg.hl();
    }

    pub fn op_ccf(&mut self) {
        self.reg.set_n(false);
        self.reg.set_h(false);
        self.reg.set_c(!self.reg.c());
    }

    pub fn op_scf(&mut self) {
        self.reg.set_n(false);
        self.reg.set_h(false);
        self.reg.set_c(true);
    }

    pub fn op_cpl(&mut self) {
        self.reg.set_n(true);
        self.reg.set_h(true);
    }

    pub fn x8_alu_and(&mut self, lhs: u8, rhs: u8) -> u8 {
        let result = lhs & rhs;
        self.reg.set_z(result == 0);
        self.reg.set_n(false);
        self.reg.set_h(true);
        self.reg.set_c(false);

        result
    }

    pub fn x8_alu_xor(&mut self, lhs: u8, rhs: u8) -> u8 {
        let result = lhs ^ rhs;
        self.reg.set_z(result == 0);
        self.reg.set_n(false);
        self.reg.set_h(false);
        self.reg.set_c(false);

        result
    }

    pub fn x8_alu_or(&mut self, lhs: u8, rhs: u8) -> u8 {
        let result = lhs ^ rhs;
        self.reg.set_z(result == 0);
        self.reg.set_n(false);
        self.reg.set_h(false);
        self.reg.set_c(false);

        result
    }

    pub fn x8_alu_cp(&mut self, lhs: u8, rhs: u8)  {
        let result = lhs.wrapping_sub(rhs);
        
        //println!("CP: {:02X} - {:02X} : {:02X}", lhs, rhs, result);

        self.reg.set_z(result == 0);
        self.reg.set_n(true);
        self.reg.set_h(u8::wrapping_sub(lhs & 0xF, rhs & 0xF) & 0x10 != 0);
        self.reg.set_c(rhs > lhs);


    }

    pub fn x8_rra(&mut self) -> u8 {
        let carry = self.reg.a & 0b0000001 != 0;

        let mut result = self.reg.a >> 1;

        result |= (self.reg.c() as u8) << 7;

        self.reg.set_c(carry);
        self.reg.set_z(false);
        self.reg.set_n(false);
        self.reg.set_h(false);

        return result;
    }

    pub fn x8_rla(&mut self) -> u8 {
        let carry = self.reg.a & 0b10000000 != 0;

        let mut result = self.reg.a << 1;

        result |= self.reg.c() as u8;

        self.reg.set_c(carry);
        self.reg.set_z(false);
        self.reg.set_n(false);
        self.reg.set_h(false);

        return result;
    }

    pub fn x8_rrca(&mut self) -> u8 {
        let carry = self.reg.a & 0b0000001 != 0;
        let result = self.reg.a.rotate_right(1);

        self.reg.set_c(carry);
        self.reg.set_z(false);
        self.reg.set_n(false);
        self.reg.set_h(false);

        result
    }

    pub fn x8_rlca(&mut self) -> u8 {
        let carry = self.reg.a & 0b10000000 != 0;
        let result = self.reg.a.rotate_left(1);

        self.reg.set_c(carry);
        self.reg.set_z(false);
        self.reg.set_n(false);
        self.reg.set_h(false);

        result
    }


    pub fn x8_rr(&mut self, value: u8) -> u8 {
        let carry = value & 0b0000001 == 0;

        let mut result = value >> 1;

        result |= (self.reg.c() as u8) << 7;

        self.reg.set_c(carry);
        self.reg.set_z(result == 0);
        self.reg.set_n(false);
        self.reg.set_h(false);

        return result;
    }

    pub fn x8_rl(&mut self, value: u8) -> u8 {
        let carry = value & 0b10000000 != 0;

        let mut result = value << 1;

        result |= self.reg.c() as u8;

        self.reg.set_c(carry);
        self.reg.set_z(result == 0);
        self.reg.set_n(false);
        self.reg.set_h(false);

        return result;
    }

    pub fn x8_rrc(&mut self, value: u8) -> u8 {
        let carry = value & 0b0000001 == 0;
        let result = value.rotate_right(1);

        self.reg.set_c(carry);
        self.reg.set_z(result == 0);
        self.reg.set_n(false);
        self.reg.set_h(false);

        result
    }

    pub fn x8_rlc(&mut self, value: u8) -> u8 {
        let carry = value & 0b10000000 != 0;
        let result = value.rotate_left(1);

        self.reg.set_c(carry);
        self.reg.set_z(result == 0);
        self.reg.set_n(false);
        self.reg.set_h(false);

        result
    }

    pub fn x8_alu_sub(&mut self, lhs: u8, rhs: u8) -> u8 {
        let result = lhs.wrapping_sub(rhs);

        self.reg.set_z(result == 0);
        self.reg.set_n(false);
        self.reg.set_h(u8::wrapping_sub(lhs & 0xF, rhs & 0xF) & 0x10 != 0);
        self.reg.set_c(rhs > lhs);

        result
    }

    pub fn x8_alu_sbc(&mut self, lhs: u8, rhs: u8) -> u8 {
 
        let result = lhs.wrapping_sub(rhs);

        
        self.reg.set_n(false);
        self.reg.set_h(u8::wrapping_sub(lhs & 0xF, rhs & 0xF).wrapping_sub(self.reg.c() as u8) & 0x10 != 0);
        self.reg.set_z(result == 0);
        self.reg.set_c(rhs.wrapping_sub(self.reg.c() as u8) > lhs);

        result
    }

    pub fn x8_alu_add(&mut self, lhs: u8, rhs: u8) -> u8 {
        let (result, carry) = lhs.overflowing_add(rhs);

        self.reg.set_z(result == 0);
        self.reg.set_n(false);
        self.reg.set_h((lhs & 0xF) + (rhs & 0xF) > 0xF);
        self.reg.set_c(carry);

        result
    }

    pub fn x8_alu_adc(&mut self, lhs: u8, rhs: u8) -> u8 {
        let (result, carry_add) = lhs.overflowing_add(rhs);
        let (result, carry_c) = result.overflowing_add(self.reg.z() as u8);

        self.reg.set_h((lhs & 0xF) + (rhs & 0xF) + (self.reg.c()) as u8 > 0xF);
        self.reg.set_z(result == 0);
        self.reg.set_n(false);
        self.reg.set_c(carry_add | carry_c);

        result
    }

    pub fn x8_alu_inc(&mut self, value: u8) -> u8 {
        let result = value.wrapping_add(1);

        self.reg.set_z(result == 0);
        self.reg.set_n(false);
        self.reg.set_h(result == 0x10);

        result
    }

    pub fn x8_alu_dec(&mut self, value: u8) -> u8 {
        let result = value.wrapping_sub(1);

        self.reg.set_z(result == 0);
        self.reg.set_n(true);
        self.reg.set_h(result == 0x0F);

        result
    }

    pub fn x16_alu_add(&mut self, lhs: u16, rhs: u16) -> u16 {
        let (result, carry) = lhs.overflowing_add(rhs);
        
        self.reg.set_n(false);
        self.reg.set_c(carry);
        self.reg.set_h((lhs & 0xFFF) + (rhs & 0xFFF) > 0xFFF);

        result
    }

    pub fn x16_alu_inc(&mut self, value: u16) -> u16 {
        self.clock();
        value.wrapping_add(1)
    }

    pub fn x16_alu_dec(&mut self, value: u16) -> u16 {
        self.clock();
        value.wrapping_add(1)
    }

    pub fn dump(&self) {
        println!("Cycle: {:010} PC: {:04X} AF: {:04x} BC: {:04x} DE: {:04X} HL: {:04X} SP: {:04x} Z: {}, N: {}, H: {}, C: {}", self.cycles, self.reg.pc, self.reg.af(), self.reg.bc(), self.reg.de(), self.reg.hl(),
        self.reg.sp,
        self.reg.z() as u8,
        self.reg.n() as u8,
        self.reg.h() as u8,
        self.reg.c() as u8
    );
    }
}

pub struct MMU {
    ROM0: [u8; 0x4000],
    ROM1: [u8; 0x4000],
    VRAM: [u8; 0x2000],
    EXRAM: [u8; 0x2000],
    WRAM0: [u8; 0x1000],
    WRAM1: [u8; 0x1000],
    OAM: [u8; 0xA0],
    IOREG: [u8; 0x80],
    HRAM: [u8; 0x7F],
    IE: u8
}

impl MMU {

    pub fn new() -> Self {
        Self {
            ROM0: [0x0u8; 0x4000],
            ROM1: [0xFFu8; 0x4000],
            VRAM: [0xFFu8; 0x2000],
            EXRAM: [0xFFu8; 0x2000],
            WRAM0: [0xFFu8; 0x1000],
            WRAM1: [0xFFu8; 0x1000],
            OAM: [0xFFu8; 0xA0],
            IOREG: [0xFFu8; 0x80],
            HRAM: [0xFFu8; 0x7F],
            IE: 0xFF
        }
    }

    pub fn write(&mut self, addr: u16, value: u8) {
        match addr {
            0x8000..=0x9FFF => self.VRAM[(addr - 0x8000) as usize] = value,
            0xA000..=0xBFFF => self.EXRAM[(addr - 0xA000) as usize] = value,
            0xC000..=0xCFFF => self.WRAM0[(addr - 0xC000) as usize] = value,
            0xD000..=0xDFFF => self.WRAM1[(addr - 0xD000) as usize] = value,
            0xFE00..=0xFE9F => self.OAM[(addr - 0xFE00) as usize] = value,
            0xFF00..=0xFF7F => self.IOREG[(addr - 0xFF00) as usize] = value,
            0xFF80..=0xFFFE => self.HRAM[(addr - 0xFF80) as usize] = value,
            0xFFFF => self.IE = value,
            _ => { }
        }
    }

    pub fn read(&self, addr: u16) -> u8 {
        match addr {
            0x0000..=0x3FFF => self.ROM0[addr as usize],
            0x4000..=0x7FFF => self.ROM1[(addr - 0x4000) as usize],
            0x8000..=0x9FFF => self.VRAM[(addr - 0x8000) as usize],
            0xA000..=0xBFFF => self.EXRAM[(addr - 0xA000) as usize],
            0xC000..=0xCFFF => self.WRAM0[(addr - 0xC000) as usize],
            0xD000..=0xDFFF => self.WRAM1[(addr - 0xD000) as usize],
            0xFE00..=0xFE9F => self.OAM[(addr - 0xFE00) as usize],
            0xFF00..=0xFF7F => self.IOREG[(addr - 0xFF00) as usize],
            0xFF80..=0xFFFE => self.HRAM[(addr - 0xFF80) as usize],
            0xFFFF => self.IE,
            _ => { 0xFF }
        }
    }
}

pub struct GPU {
    ly: u8,
    dots: u16,
    image: [u32; 256 * 256],
    //front_buffer: usize,
    //back_buffer: usize
}

impl GPU {
    pub fn new() -> Self {
        
        Self {
            dots: 0,
            ly: 0,
            image: [0xFFFFFFFFu32; 256 * 256],
            //front_buffer: 0,
            //back_buffer: 1
        }
    }

    pub fn tick(&mut self, mmu: &mut MMU, cycles: u64) {
        mmu.write(0xFF44, self.ly);

        self.dots += cycles as u16;

        if self.dots > 456  {
            self.dots = 0;
            self.draw_line(mmu);
            self.ly += 1;
        }

        if self.ly > 153 {
            //std::mem::swap(&mut self.front_buffer, &mut self.back_buffer);
            //self.image[self.back_buffer] = [0xFFFFFFFFu32; 256 * 256];
            //self.front_buffer = self.back_buffer;

            self.ly = 0;
        }
    }

    pub fn get_tile_pixel(&mut self, mmu: &MMU, tile: u8, x: u16, y: u16) -> bool {
        let addr = 0x8000 + (tile as u16) * 16 + y * 2;

        let plane1 = mmu.read(addr);
        let plane2 = mmu.read(addr + 1);

        let mask = 1 << (7 - x);

        if mask & plane1 != 0 || mask & plane2 != 0 {
            return true;
        } else {
            return false;
        }
    }

    pub fn draw_line(&mut self, mmu: &MMU) {
        let scy = mmu.read(0xFF42);
        for x in 0..256 {
            let tile_x = x / 8;
            let tile_y = self.ly / 8;

            let tile = mmu.read(0x9800 + tile_x as u16 + tile_y as u16 * 32);

            let mut pixel = 0xFFFFFFFFu32;
            
            if tile != 0 {
                //println!("tile_x {}, tile_y {}, tile {}, tile_addr {:04X}", tile_x, tile_y, tile, 0x9800 + tile_x as u16 + tile_y as u16 * 32);
                let color = self.get_tile_pixel(mmu, tile, x % 8, (self.ly as u16) % 8);
                if (color) {
                    pixel = 0xFF000000u32; //rgba
                }
            

                
            }

            self.image[x as usize + ((self.ly - scy) as usize % 256) as usize * 256] = pixel;
        }
    }
}

/*fn main() {
    let mmu = MMU::new();

    let mut cpu = CPU::new(mmu);

    cpu.load("DMG_ROM.bin");
    let mut iterations = 0usize;

    loop {
        //if (cpu.reg.pc > 0x0095) {


            iterations += 1;

            if iterations % 1000000 == 0 {


            println!("Cycle: {:010} PC: {:04X} AF: {:04x} BC: {:04x} DE: {:04X} HL: {:04X} SP: {:04x} Z: {}, N: {}, H: {}, C: {}", cpu.cycles, cpu.reg.pc, cpu.reg.af(), cpu.reg.bc(), cpu.reg.de(), cpu.reg.hl(),
            cpu.reg.sp,
            cpu.reg.z() as u8,
            cpu.reg.n() as u8,
            cpu.reg.h() as u8,
            cpu.reg.c() as u8
        );
    }
            let mut buf = String::new();
            //std::io::stdin().read_line(&mut buf);
        //}
        cpu.step();
    }

}*/

use ggez::{Context, ContextBuilder, GameResult};
use ggez::graphics::{self, Color, Image, DrawParam};
use ggez::event::{self, EventHandler};

fn main() {
    // Make a Context.
    let (mut ctx, event_loop) = ContextBuilder::new("my_game", "Cool Game Author")
        .build()
        .expect("aieee, could not create ggez context!");

    // Create an instance of your event handler.
    // Usually, you should provide it with the Context object to
    // use when setting your game up.
    let my_game = MyGame::new(&mut ctx);

    // Run!
    event::run(ctx, event_loop, my_game);
}

struct MyGame {
    cpu: Box<CPU>
}

impl MyGame {
    pub fn new(_ctx: &mut Context) -> MyGame {
        let mmu = MMU::new();

        let mut cpu = Box::new(CPU::new(mmu));
    
        cpu.load("DMG_ROM.bin");
        MyGame {
            cpu: cpu
        }
    }
}

impl EventHandler for MyGame {
    fn update(&mut self, _ctx: &mut Context) -> GameResult<()> {

        let cycles = self.cpu.cycles;
        while(self.cpu.cycles < cycles + 28000) {
            self.cpu.step();
        }
        Ok(())
    }

    fn draw(&mut self, ctx: &mut Context) -> GameResult<()> {
        
        
        unsafe {



                graphics::clear(ctx, Color::BLACK);
                let bytes = std::mem::transmute::<[u32; 256 * 256], [u8; 256 * 256 * 4]>(self.cpu.gpu.image);

                let img = Image::from_rgba8(ctx, 256, 256, &bytes)?;

                graphics::draw(ctx, &img, DrawParam::default());
                

        }
        graphics::present(ctx)
        
    }
}