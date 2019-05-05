package com.blossom.accountvault;

import java.security.SecureRandom;

/**
 * file: AESCipher
 * author: Dan Blossom
 * course: MSCS 630 Security Algorithms & Protocols
 * version: 1
 * 
 * This file contains the main class driver
 */

public class AEScipher {

  /**
   * The sBox hex from the lab 
   */
  private static final int[] sBox = new int[] {
      0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
      0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
      0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
      0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
      0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
      0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
      0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
      0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
      0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
      0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
      0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
      0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
      0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
      0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
      0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
      0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
  };
  
  /**
   * The inverse s-box needed to reverse what the s-box did.
   * For Reference see: https://en.wikipedia.org/wiki/Rijndael_S-box
   */
  private static final int[] inverseSbox = new int[] {
      0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
      0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
      0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
      0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
      0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
      0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
      0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
      0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
      0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
      0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
      0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
      0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
      0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
      0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
      0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
      0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
  };
  
  /**
   * The rcon hex from the lab
   */
  private static final int[] rCon = new int[] {
      0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
      0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
      0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
      0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
      0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
      0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
      0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
      0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
      0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
      0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
      0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
      0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
      0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
      0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
      0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
      0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d
  };
  
  /**
   * Rijndael Mix Column multiply by 9 lookup table as seen:
   * https://ipfs.io/ipfs/QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco/wiki/Rijndael_mix_columns.html
   */
  private static final int[] multByNine = new int[] {
    0x00,0x09,0x12,0x1b,0x24,0x2d,0x36,0x3f,0x48,0x41,0x5a,0x53,0x6c,0x65,0x7e,0x77,
    0x90,0x99,0x82,0x8b,0xb4,0xbd,0xa6,0xaf,0xd8,0xd1,0xca,0xc3,0xfc,0xf5,0xee,0xe7,
    0x3b,0x32,0x29,0x20,0x1f,0x16,0x0d,0x04,0x73,0x7a,0x61,0x68,0x57,0x5e,0x45,0x4c,
    0xab,0xa2,0xb9,0xb0,0x8f,0x86,0x9d,0x94,0xe3,0xea,0xf1,0xf8,0xc7,0xce,0xd5,0xdc,
    0x76,0x7f,0x64,0x6d,0x52,0x5b,0x40,0x49,0x3e,0x37,0x2c,0x25,0x1a,0x13,0x08,0x01,
    0xe6,0xef,0xf4,0xfd,0xc2,0xcb,0xd0,0xd9,0xae,0xa7,0xbc,0xb5,0x8a,0x83,0x98,0x91,
    0x4d,0x44,0x5f,0x56,0x69,0x60,0x7b,0x72,0x05,0x0c,0x17,0x1e,0x21,0x28,0x33,0x3a,
    0xdd,0xd4,0xcf,0xc6,0xf9,0xf0,0xeb,0xe2,0x95,0x9c,0x87,0x8e,0xb1,0xb8,0xa3,0xaa,
    0xec,0xe5,0xfe,0xf7,0xc8,0xc1,0xda,0xd3,0xa4,0xad,0xb6,0xbf,0x80,0x89,0x92,0x9b,
    0x7c,0x75,0x6e,0x67,0x58,0x51,0x4a,0x43,0x34,0x3d,0x26,0x2f,0x10,0x19,0x02,0x0b,
    0xd7,0xde,0xc5,0xcc,0xf3,0xfa,0xe1,0xe8,0x9f,0x96,0x8d,0x84,0xbb,0xb2,0xa9,0xa0,
    0x47,0x4e,0x55,0x5c,0x63,0x6a,0x71,0x78,0x0f,0x06,0x1d,0x14,0x2b,0x22,0x39,0x30,
    0x9a,0x93,0x88,0x81,0xbe,0xb7,0xac,0xa5,0xd2,0xdb,0xc0,0xc9,0xf6,0xff,0xe4,0xed,
    0x0a,0x03,0x18,0x11,0x2e,0x27,0x3c,0x35,0x42,0x4b,0x50,0x59,0x66,0x6f,0x74,0x7d,
    0xa1,0xa8,0xb3,0xba,0x85,0x8c,0x97,0x9e,0xe9,0xe0,0xfb,0xf2,0xcd,0xc4,0xdf,0xd6,
    0x31,0x38,0x23,0x2a,0x15,0x1c,0x07,0x0e,0x79,0x70,0x6b,0x62,0x5d,0x54,0x4f,0x46
  };
  
  /**
   * Rijndael Mix Column multiply by 11 lookup table as seen:
   * https://ipfs.io/ipfs/QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco/wiki/Rijndael_mix_columns.html
   */
  private static final int[] multByEleven = new int[] {
      0x00,0x0b,0x16,0x1d,0x2c,0x27,0x3a,0x31,0x58,0x53,0x4e,0x45,0x74,0x7f,0x62,0x69,
      0xb0,0xbb,0xa6,0xad,0x9c,0x97,0x8a,0x81,0xe8,0xe3,0xfe,0xf5,0xc4,0xcf,0xd2,0xd9,
      0x7b,0x70,0x6d,0x66,0x57,0x5c,0x41,0x4a,0x23,0x28,0x35,0x3e,0x0f,0x04,0x19,0x12,
      0xcb,0xc0,0xdd,0xd6,0xe7,0xec,0xf1,0xfa,0x93,0x98,0x85,0x8e,0xbf,0xb4,0xa9,0xa2,
      0xf6,0xfd,0xe0,0xeb,0xda,0xd1,0xcc,0xc7,0xae,0xa5,0xb8,0xb3,0x82,0x89,0x94,0x9f,
      0x46,0x4d,0x50,0x5b,0x6a,0x61,0x7c,0x77,0x1e,0x15,0x08,0x03,0x32,0x39,0x24,0x2f,
      0x8d,0x86,0x9b,0x90,0xa1,0xaa,0xb7,0xbc,0xd5,0xde,0xc3,0xc8,0xf9,0xf2,0xef,0xe4,
      0x3d,0x36,0x2b,0x20,0x11,0x1a,0x07,0x0c,0x65,0x6e,0x73,0x78,0x49,0x42,0x5f,0x54,
      0xf7,0xfc,0xe1,0xea,0xdb,0xd0,0xcd,0xc6,0xaf,0xa4,0xb9,0xb2,0x83,0x88,0x95,0x9e,
      0x47,0x4c,0x51,0x5a,0x6b,0x60,0x7d,0x76,0x1f,0x14,0x09,0x02,0x33,0x38,0x25,0x2e,
      0x8c,0x87,0x9a,0x91,0xa0,0xab,0xb6,0xbd,0xd4,0xdf,0xc2,0xc9,0xf8,0xf3,0xee,0xe5,
      0x3c,0x37,0x2a,0x21,0x10,0x1b,0x06,0x0d,0x64,0x6f,0x72,0x79,0x48,0x43,0x5e,0x55,
      0x01,0x0a,0x17,0x1c,0x2d,0x26,0x3b,0x30,0x59,0x52,0x4f,0x44,0x75,0x7e,0x63,0x68,
      0xb1,0xba,0xa7,0xac,0x9d,0x96,0x8b,0x80,0xe9,0xe2,0xff,0xf4,0xc5,0xce,0xd3,0xd8,
      0x7a,0x71,0x6c,0x67,0x56,0x5d,0x40,0x4b,0x22,0x29,0x34,0x3f,0x0e,0x05,0x18,0x13,
      0xca,0xc1,0xdc,0xd7,0xe6,0xed,0xf0,0xfb,0x92,0x99,0x84,0x8f,0xbe,0xb5,0xa8,0xa3
  };
  
  /**
   * Rijndael Mix Column multiply by 13 lookup table as seen:
   * https://ipfs.io/ipfs/QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco/wiki/Rijndael_mix_columns.html
   */
  private static final int[] multByThirteen = new int[] {
      0x00,0x0d,0x1a,0x17,0x34,0x39,0x2e,0x23,0x68,0x65,0x72,0x7f,0x5c,0x51,0x46,0x4b,
      0xd0,0xdd,0xca,0xc7,0xe4,0xe9,0xfe,0xf3,0xb8,0xb5,0xa2,0xaf,0x8c,0x81,0x96,0x9b,
      0xbb,0xb6,0xa1,0xac,0x8f,0x82,0x95,0x98,0xd3,0xde,0xc9,0xc4,0xe7,0xea,0xfd,0xf0,
      0x6b,0x66,0x71,0x7c,0x5f,0x52,0x45,0x48,0x03,0x0e,0x19,0x14,0x37,0x3a,0x2d,0x20,
      0x6d,0x60,0x77,0x7a,0x59,0x54,0x43,0x4e,0x05,0x08,0x1f,0x12,0x31,0x3c,0x2b,0x26,
      0xbd,0xb0,0xa7,0xaa,0x89,0x84,0x93,0x9e,0xd5,0xd8,0xcf,0xc2,0xe1,0xec,0xfb,0xf6,
      0xd6,0xdb,0xcc,0xc1,0xe2,0xef,0xf8,0xf5,0xbe,0xb3,0xa4,0xa9,0x8a,0x87,0x90,0x9d,
      0x06,0x0b,0x1c,0x11,0x32,0x3f,0x28,0x25,0x6e,0x63,0x74,0x79,0x5a,0x57,0x40,0x4d,
      0xda,0xd7,0xc0,0xcd,0xee,0xe3,0xf4,0xf9,0xb2,0xbf,0xa8,0xa5,0x86,0x8b,0x9c,0x91,
      0x0a,0x07,0x10,0x1d,0x3e,0x33,0x24,0x29,0x62,0x6f,0x78,0x75,0x56,0x5b,0x4c,0x41,
      0x61,0x6c,0x7b,0x76,0x55,0x58,0x4f,0x42,0x09,0x04,0x13,0x1e,0x3d,0x30,0x27,0x2a,
      0xb1,0xbc,0xab,0xa6,0x85,0x88,0x9f,0x92,0xd9,0xd4,0xc3,0xce,0xed,0xe0,0xf7,0xfa,
      0xb7,0xba,0xad,0xa0,0x83,0x8e,0x99,0x94,0xdf,0xd2,0xc5,0xc8,0xeb,0xe6,0xf1,0xfc,
      0x67,0x6a,0x7d,0x70,0x53,0x5e,0x49,0x44,0x0f,0x02,0x15,0x18,0x3b,0x36,0x21,0x2c,
      0x0c,0x01,0x16,0x1b,0x38,0x35,0x22,0x2f,0x64,0x69,0x7e,0x73,0x50,0x5d,0x4a,0x47,
      0xdc,0xd1,0xc6,0xcb,0xe8,0xe5,0xf2,0xff,0xb4,0xb9,0xae,0xa3,0x80,0x8d,0x9a,0x97
  };
  
  /**
   * Rijndael Mix Column multiply by 14 lookup table as seen:
   * https://ipfs.io/ipfs/QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco/wiki/Rijndael_mix_columns.html
   */
  private static final int[] multByFourteen = new int[] {
      0x00,0x0e,0x1c,0x12,0x38,0x36,0x24,0x2a,0x70,0x7e,0x6c,0x62,0x48,0x46,0x54,0x5a,
      0xe0,0xee,0xfc,0xf2,0xd8,0xd6,0xc4,0xca,0x90,0x9e,0x8c,0x82,0xa8,0xa6,0xb4,0xba,
      0xdb,0xd5,0xc7,0xc9,0xe3,0xed,0xff,0xf1,0xab,0xa5,0xb7,0xb9,0x93,0x9d,0x8f,0x81,
      0x3b,0x35,0x27,0x29,0x03,0x0d,0x1f,0x11,0x4b,0x45,0x57,0x59,0x73,0x7d,0x6f,0x61,
      0xad,0xa3,0xb1,0xbf,0x95,0x9b,0x89,0x87,0xdd,0xd3,0xc1,0xcf,0xe5,0xeb,0xf9,0xf7,
      0x4d,0x43,0x51,0x5f,0x75,0x7b,0x69,0x67,0x3d,0x33,0x21,0x2f,0x05,0x0b,0x19,0x17,
      0x76,0x78,0x6a,0x64,0x4e,0x40,0x52,0x5c,0x06,0x08,0x1a,0x14,0x3e,0x30,0x22,0x2c,
      0x96,0x98,0x8a,0x84,0xae,0xa0,0xb2,0xbc,0xe6,0xe8,0xfa,0xf4,0xde,0xd0,0xc2,0xcc,
      0x41,0x4f,0x5d,0x53,0x79,0x77,0x65,0x6b,0x31,0x3f,0x2d,0x23,0x09,0x07,0x15,0x1b,
      0xa1,0xaf,0xbd,0xb3,0x99,0x97,0x85,0x8b,0xd1,0xdf,0xcd,0xc3,0xe9,0xe7,0xf5,0xfb,
      0x9a,0x94,0x86,0x88,0xa2,0xac,0xbe,0xb0,0xea,0xe4,0xf6,0xf8,0xd2,0xdc,0xce,0xc0,
      0x7a,0x74,0x66,0x68,0x42,0x4c,0x5e,0x50,0x0a,0x04,0x16,0x18,0x32,0x3c,0x2e,0x20,
      0xec,0xe2,0xf0,0xfe,0xd4,0xda,0xc8,0xc6,0x9c,0x92,0x80,0x8e,0xa4,0xaa,0xb8,0xb6,
      0x0c,0x02,0x10,0x1e,0x34,0x3a,0x28,0x26,0x7c,0x72,0x60,0x6e,0x44,0x4a,0x58,0x56,
      0x37,0x39,0x2b,0x25,0x0f,0x01,0x13,0x1d,0x47,0x49,0x5b,0x55,0x7f,0x71,0x63,0x6d,
      0xd7,0xd9,0xcb,0xc5,0xef,0xe1,0xf3,0xfd,0xa7,0xa9,0xbb,0xb5,0x9f,0x91,0x83,0x8d
  };
  
  /**
   * An empty constructor
   */
  public AEScipher() {}
  
  /**
   * The main method of this class
   * @param keyHex The Key Hex passed in to create the 11 round keys
   * @return The 11 round keys created from the input string
   */
  public String[] aesRoundKeys(String keyHex) {
    // first we build the K matric 
    String[][] kMatrix = buildKMatrix(keyHex);
    // now we need the W matrix - lets init it
    String[][] wMatrix = initalizeWMatrix(kMatrix);
    // build the remaining columns of W matrix
    buildRemainingWColumns(wMatrix);
    // generate the round keys from W matrix and return to caller
    return generateRoundKeys(wMatrix);
  }
  
  /**
   * A method that will perform AES encryption using figure 1 flow
   * in lab as a basis for algorithm
   * 
   * @param pTextHex the plain text block
   * @param keyHex the system key
   * @return the encrypted text/key
   */
  public String AES(String pTextHex, String keyHex) {
    
    // SO - following the flow chart in the lab
    // and help from text book IC the algorithm
    // has 3 main parts, round 0, round 1-9, round 10
    
    // Round 0 - convert input to matrix & XOR.
    String[] keys = aesRoundKeys(keyHex);
    // built this for building K matrix but it'll work here :)
    String[][] plainTextBlock = buildKMatrix(pTextHex);
    String[][] keyBlock = buildKMatrix(keys[0]);
    String[][] outStateHex = AESStateXOR(plainTextBlock, keyBlock);
    
    // Rounds 1 - 9:
    // Nibble, shift, Mix, Add key
    for(int i = 1; i < keys.length-1; i++) {
      outStateHex = AESNibbleSub(outStateHex);
      outStateHex = AESShiftRow(outStateHex);
      outStateHex = AESMixColumn(outStateHex);
      keyBlock = buildKMatrix(keys[i]);
      outStateHex = AESStateXOR(outStateHex, keyBlock);
    }
    
    // Round 10:
    // We nibble, shift and add key (skip mix step)
    // Since we only don't mix, a simple 'if' in for loop would
    // work perfect, but want to break out algo like book/lab
    outStateHex = AESNibbleSub(outStateHex);
    outStateHex = AESShiftRow(outStateHex);
    keyBlock = buildKMatrix(keys[10]);
    outStateHex = AESStateXOR(outStateHex, keyBlock);
    
    // AND - we return!
    return hexStringBuilder(outStateHex);
  }
  
  /**
   * A Method that will perform AES Decryption on a 128 bit
   * hex string - basically the reverse of AES method above
   * 
   * @param encryptedText the encrypted text to decrypt
   * @param encryptionKey the key used to encrypt
   * @return plainHex the decrypted string in hex
   */
  public String aesDecrypt(String encryptedText, String encryptionKey) {
	  
	  // First we need to setup all variables like before
	  String[] keys = aesRoundKeys(encryptionKey);
	  String[][] encryptedBlock = buildKMatrix(encryptedText);
	  String[][] keyBlock = buildKMatrix(keys[10]);
	  String[][] outStateHex = AESStateXOR(encryptedBlock, keyBlock);
	  
	  // We need to perform the last nibble and shiftrow first
	  // Also they need to be in reverse order from previous
	  outStateHex = reverseAESShiftRow(outStateHex);
	  outStateHex = reverseAESNibbleSub(outStateHex);
	  
    // Rounds 9 - 1:
    // Nibble, shift, Mix, Add key
    for(int i = 9; i > 0; i--) {
      keyBlock = buildKMatrix(keys[i]);
      outStateHex = AESStateXOR(outStateHex, keyBlock);
      
      outStateHex = reverseAESMixColumn(outStateHex);
      
      outStateHex = reverseAESShiftRow(outStateHex);
      
      outStateHex = reverseAESNibbleSub(outStateHex);
    }

    keyBlock = buildKMatrix(keys[0]);
    outStateHex = AESStateXOR(outStateHex, keyBlock);
    
    // AND - we return!
    return hexStringBuilder(outStateHex);
  }
  
  /**
   * A method that will allow allow us to break up into multiple
   * 128 bit chunks or pad if less than 128 bits. It will take a
   * plain string, convert it to HEX and break into 16 byte(128 bit)
   * chunks for the AES function.
   * 
   * @param inputText the plain text string to encrypt
   * @param key the key used to encrypt
   */
  public String encrypt(String inputText, String key) {
	  
	  int padLength = (16 - (inputText.length() % 16)) + inputText.length();
	  
	  if(padLength != (inputText.length() + 16)) {
		  inputText = padString(inputText, " ", padLength);
	  }
	  
	  // the array to hold the converted plain text to hex
	  String[] hexArray = new String[inputText.length() / 16];
	  int hexArrayPointer = 0;
	  
	  // Let's break the input plain text into chunks
	  // of 16 bytes, 1 byte for each character our AES function
	  while(inputText.length() > 0) {
		  // get the first 16 byte chunk
		  String chunk = inputText.substring(0, 16);
		  // concat string for next pass
		  inputText = inputText.substring(16, inputText.length());
		  StringBuffer asciiToHexString = new StringBuffer();
		  for(int i = 0; i < chunk.length(); i++) {
			  asciiToHexString.append(Integer.toHexString((int) chunk.charAt(i))); 
		  }
		  hexArray[hexArrayPointer++] = asciiToHexString.toString();
	  }
	  
	  StringBuilder encryptedString = new StringBuilder();
	  
	  for(String hexString: hexArray) {
		  encryptedString.append(AES(hexString,key));
	  }
	  
	  return encryptedString.toString();
  }
  
  /*
   * This method will return an encrypted text back as
   * Plain text by breaking the hex string into 128-bit
   * blocks for the decryption algorithm then converting
   * the hex to characters.
   * @param outputText the text to be decrypted to plain
   * @param key the key used to encrypt the text
   * @return the plain text
   */
  public String decrypt(String outputText, String key) {
    
    String hexArray[] = new String[outputText.length() / 32];
    int hexArrayPointer = 0;
    
    while(outputText.length() !=0) {
      hexArray[hexArrayPointer++] = outputText.substring(0,32);
      outputText = outputText.substring(32);
    }
    
    StringBuilder decryptedString = new StringBuilder();
    
    for(String hexString: hexArray) {
      decryptedString.append(aesDecrypt(hexString,key));
    }
    
    StringBuilder decryptedText = new StringBuilder();
    
    for(int i = 0; i < decryptedString.length(); i += 2) {
      decryptedText.append( (char) Integer.parseInt(decryptedString.substring(i, i + 2),16));
    }
    
    return decryptedText.toString();
    
  }

  /**
   * This method will generate a random-ish key for us to use
   * @return a random AES Key at 128 bits.
   */
  public String randomKey(){
      SecureRandom secureRandom = new SecureRandom();
      StringBuilder hexString = new StringBuilder();
      while(hexString.length() < 32) {
          int randomNumber = secureRandom.nextInt(127-33) + 33;
          String hexValue = Integer.toHexString(randomNumber);
          hexString.append(hexValue);
      }
      return hexString.toString();
  }
  
  /**
   * **************************************************************
   *              HELPER FUNCTIONS BELOW
   * **************************************************************
   */
  
  /**
   * A simple method to pad a string to a length mod of 16
   * @param toPad a string to pad
   * @param padChar a character to pad
   * @return padString the string padded
   */
  private String padString(String toPad, String padChar, int length) {
	  StringBuilder returnString = new StringBuilder(toPad);
	  while(returnString.length() != length) {
		  returnString.append(padChar);
	  }
	  return returnString.toString();
  }
  
  /**
   * A simple method to return a hex value from sBox.
   * @param inHex the location in sbox to return
   * @return the value in inHex location of sbox
   */
  private String aesSBox(int inHex) {
    return Integer.toHexString(sBox[inHex]);
  }
  
  /**
   * A simple method to return a hex value from
   * the inverse sbox
   * @param inHex the hex value location to return
   * @return the value in inhex location
   */
  private String inverseAESSbox(int inHex) {
    return Integer.toHexString(inverseSbox[inHex]);
  }
  
  /**
   * A simple method that returns the rcon given a location
   * @param round the location of the rcon
   * @return the rcon at the location passed i round
   */
  private String aesRcon(int round) {
    return Integer.toHexString(rCon[round]);
  }
  
  /**
   * A method that will perform the add round key operation
   * This is done by XOR on the input matrixes
   * 
   * @param sHex the sHex 4x4 matrix
   * @param keyHex the keyHex 4x4 matrix
   * @return the created 4x4 matrix 'AES Add Key
   */
  private String[][] AESStateXOR(String[][] sHex, String[][] keyHex){
    // the outstatehex we are returning
    String outStateHex[][] = new String[4][4];
    
    // loop through and xor sHex and keyHex and add to return matrix
    for(int i = 0; i < outStateHex.length; i++) {
      for(int j = 0; j < outStateHex[0].length; j++) {
        outStateHex[i][j] = xorExtended(sHex[i][j],keyHex[i][j]);
      }
    }
    // Finally return
    return outStateHex;
  }
  
  /**
   * A method that will perform substitution operation from the 
   * input matrix via the aesSBox(int) method
   * 
   * @param inStateHex the matrix to perform the substitution on
   * @return the new matrix with substituted values.
   */
  private String[][] AESNibbleSub(String[][] inStateHex){
    // the outstatehex 4x4 matrix we are returning
    String outStateHex[][] = new String[4][4];
    
    // loop through performing the subs
    for(int i = 0; i < outStateHex.length; i++) {
      for(int j = 0; j < outStateHex[0].length; j++) {
        outStateHex[i][j] = aesSBox(Integer.parseInt(inStateHex[i][j],16));
      }
    }
    return outStateHex;
  }
  
  /**
   * A method that will perform the substitution operation from
   * the input matrix via the inverse sbox found in wiki:
   * https://en.wikipedia.org/wiki/Rijndael_S-box
   */
  private String[][] reverseAESNibbleSub(String[][] inStateHex){
    String outStateHex[][] = new String[4][4];
    
    // loop through performing the subs
    for(int i = 0; i < outStateHex.length; i++) {
      for(int j = 0; j < outStateHex[0].length; j++) {
        outStateHex[i][j] = inverseAESSbox(Integer.parseInt(inStateHex[i][j],16));
      }
    }
    return outStateHex;
  }
  
  /**
   * A method that will perform the AES Shift on a 4x4 matrix
   * 
   * @param inStateHex the matrix to perform the shift on
   * @return outStateHex the matrix after shifting
   */
  private String[][] AESShiftRow(String[][] inStateHex){
    
    // the returning matrix -- outStateHex
    String outStateHex[][] = new String[4][4];
    
    // Loop through performing the shift one column at a time
    for(int j = 0; j < outStateHex.length; j++) {
      // first row/column stays
      outStateHex[0][j] = inStateHex[0][j];
      // the rest shift by it's location - we mod 
      // because it's a multiple of 4 and its remainder
      // will be the correct index.
      outStateHex[1][j] = inStateHex[1][(j+1) % 4];
      outStateHex[2][j] = inStateHex[2][(j+2) % 4];
      outStateHex[3][j] = inStateHex[3][(j+3) % 4];
    }
    // returning outStateHex matrix
    return outStateHex;
  }
  
  private String[][] reverseAESShiftRow(String[][] inStateHex){
    // the returning matrix -- outStateHex
    String outStateHex[][] = new String[4][4];
    
    // Loop through performing the shift one column at a time
    for(int j = 0; j < outStateHex.length; j++) {
      // first row/column stays
      outStateHex[0][j] = inStateHex[0][j];
      // the rest shift by it's location - we mod 
      // because it's a multiple of 4 and its remainder
      // will be the correct index.
      outStateHex[1][j] = inStateHex[1][(j+3) % 4];
      outStateHex[2][j] = inStateHex[2][(j+2) % 4];
      outStateHex[3][j] = inStateHex[3][(j+1) % 4];
    }
    // returning outStateHex matrix
    return outStateHex;
  }
  
  /**
   * A method to perform the AES Mix Column algorithm
   * This algorithm was build with the help of the following
   * wikipedia article:
   * https://en.wikipedia.org/wiki/Rijndael_MixColumns
   * 
   * @param inStateHex the input matrix to perform mix column
   * @return the matrix after the mix column is complete
   */
  private String[][] AESMixColumn(String[][] inStateHex){
    String[][] outStateHex = new String[4][4];
    
    // XOR with Galois Multiplication
    for(int i = 0; i < outStateHex.length; i++) {
      // Ugh, this is just awful :/ I feel just renaming the helper
      // function would reduce this A LOT ... galMult or something.
      // maybe make a temp matrix with ints to reduce the Integer.parseInt
      // calls as well ... For now, just trying to get this algo working!
      outStateHex[0][i] = Integer.toHexString(
          galoisMultiplication(0x02, Integer.parseInt(
                                      inStateHex[0][i],16)) ^ 
          galoisMultiplication(0x03, Integer.parseInt(
                                      inStateHex[1][i],16)) ^
          Integer.parseInt(inStateHex[2][i],16) ^
          Integer.parseInt(inStateHex[3][i],16));

      outStateHex[1][i] = Integer.toHexString(
          Integer.parseInt(inStateHex[0][i],16) ^
          galoisMultiplication(0x02, Integer.parseInt(
                                       inStateHex[1][i],16)) ^ 
          galoisMultiplication(0x03, Integer.parseInt(
                                       inStateHex[2][i],16)) ^
          Integer.parseInt(inStateHex[3][i],16));

      outStateHex[2][i] = Integer.toHexString(
          Integer.parseInt(inStateHex[0][i],16) ^
          Integer.parseInt(inStateHex[1][i],16) ^
          galoisMultiplication(0x02, Integer.parseInt(
                                      inStateHex[2][i],16)) ^ 
          galoisMultiplication(0x03, Integer.parseInt(
                                      inStateHex[3][i],16)));

      outStateHex[3][i] = Integer.toHexString(
          galoisMultiplication(0x03, Integer.parseInt(
                                      inStateHex[0][i],16)) ^
          Integer.parseInt(inStateHex[1][i],16) ^
          Integer.parseInt(inStateHex[2][i],16) ^ 
          galoisMultiplication(0x02, Integer.parseInt(
                                      inStateHex[3][i],16)));
    }
    
    // Go fix the outStateHex to be proper 2 bytes and return.
    return fixTwoByteAfterGalMult(outStateHex);
  }
  
  /**
   * This is the inverse of the AES Mix Column....
   * A bit of research went into how to implement this ... 
   * Since I already had the 0x02 and 0x03 implementation, 
   * I tried to implement this solution using 2 ... 
   * 
   * https://crypto.stackexchange.com/questions/2569/how-does-one-implement-the-inverse-of-aes-mixcolumns
   * 
   * However, it was becoming a mess, while the tables mentioned in above didn't exist at mentioned link
   * I did find lookup tables for 9, 11, 13 & 14, see the second link
   * 
   * https://en.wikipedia.org/wiki/Rijndael_MixColumns
   * https://ipfs.io/ipfs/QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco/wiki/Rijndael_mix_columns.html
   * 
   * @param inStateHex
   * @return matrix after mix column is complete
   */
  private String[][] reverseAESMixColumn(String[][] inStateHex){
    
    String[][] outStateHex = new String[4][4];
    
    for(int i = 0; i < outStateHex.length; i++) {
      
      outStateHex[0][i] = Integer.toHexString(multByFourteen[Integer.parseInt(inStateHex[0][i],16)] ^
                                              multByEleven[Integer.parseInt(inStateHex[1][i],16)]   ^
                                              multByThirteen[Integer.parseInt(inStateHex[2][i],16)] ^
                                              multByNine[Integer.parseInt(inStateHex[3][i],16)]);
      
      outStateHex[1][i] = Integer.toHexString(multByNine[Integer.parseInt(inStateHex[0][i],16)]     ^
                                              multByFourteen[Integer.parseInt(inStateHex[1][i],16)] ^
                                              multByEleven[Integer.parseInt(inStateHex[2][i],16)]   ^ 
                                              multByThirteen[Integer.parseInt(inStateHex[3][i],16)]);

      outStateHex[2][i] = Integer.toHexString(multByThirteen[Integer.parseInt(inStateHex[0][i],16)] ^
                                              multByNine[Integer.parseInt(inStateHex[1][i],16)]     ^
                                              multByFourteen[Integer.parseInt(inStateHex[2][i],16)] ^
                                              multByEleven[Integer.parseInt(inStateHex[3][i],16)]);

      
      outStateHex[3][i] = Integer.toHexString(multByEleven[Integer.parseInt(inStateHex[0][i],16)]   ^
                                              multByThirteen[Integer.parseInt(inStateHex[1][i],16)] ^
                                              multByNine[Integer.parseInt(inStateHex[2][i],16)]     ^
                                              multByFourteen[Integer.parseInt(inStateHex[3][i],16)]);
    }
    return fixTwoByteAfterGalMult(outStateHex);
  }
  
  /**
   * A method to perform Galois Multiplication on two integers
   * reference to what helped me implement this:
   * https://en.wikipedia.org/wiki/Rijndael_MixColumns (see C# example)
   * 
   * @param firstNumber the first number to do Galois on
   * @param secondNumber the second number to do Galois on
   * @return the result from Galois multiplication
   */
  private int galoisMultiplication(int firstNumber, int secondNumber) {
    int result = 0;
    
    for(int i = 0; i < 8; i++) {
      if((secondNumber & 1) != 0) {
        result ^= firstNumber;
      }
      boolean hiBitSet = (firstNumber & 0x80) != 0;
      firstNumber <<= 1;
      if(hiBitSet) {
        firstNumber ^= 0x1b;
      }
      secondNumber >>= 1;
    }
    return result;
  }
  
  /**
   * A helper method that will fix an under/overflow
   * That seems to happen after Galois Multiplication
   * 
   * This was originally in the AESMixColumn but that was ugly enough.
   * 
   * A more detailed note about how this helper function began.
   * Through some intense debugging of many hours at multiple locations in the code
   * I tracked down a (bug?) that occurs while doing Galois Multiplication. Some, when
   * being converted back (Integer.toHexString) do not append a "0" for the two bytes, 
   * no biggie BUT sometimes we end up with three bytes and we only want the last 2 bytes.
   * The below loop will try and solve that by padidng or trimming
   */
  private String[][] fixTwoByteAfterGalMult(String[][] matrixToFix){
    for (int i = 0; i < 4; i++)
      for (int j = 0; j < 4; j++) {
        if(matrixToFix[i][j].length() < 2) {
          // append the zero
          matrixToFix[i][j] = "0".concat(matrixToFix[i][j]);
          continue;
        }
        if (matrixToFix[i][j].length() != 2) {
          matrixToFix[i][j] = matrixToFix[i][j].
                                substring(matrixToFix[i][j].length() - 2, 
                                          matrixToFix[i][j].length());
        }
      }
    return matrixToFix;
  }
  
  /**
   * A helper method to build the K matrix
   * @param keyHex the string to build the K matrix from
   * @return the K matrix from the given string
   */
  private String[][] buildKMatrix(String keyHex) {
    // the return matrix
    String[][] kMatrix = new String[4][4];
    // a pointer into the string
    int stringPointer = 0;
    // interate through the string
    for(int i = 0; i < kMatrix.length; i++) {
      for(int j = 0; j < kMatrix[0].length; j++) {
        // this is SO UNREADABLE but couldn't resist how cool/slick
        // just working down the string with the pointer and incrementing
        // along the way. At location then inc, at loc+1 then inc again 
        kMatrix[j][i] = keyHex.substring(stringPointer++, stringPointer+++1);
      }
    }
    // return the new K matrix
    return kMatrix;
  }
  
  /**
   * A helper method that will initalize the W matrix
   * @param kMatrix the K matrix to creat the W matrix from
   * @return the W matrix
   */
  private String[][] initalizeWMatrix(String[][] kMatrix){
    // the W matrix
    String wMatrix[][] = new String[4][44];
    // Iterate through K populating W
    for(int i = 0; i < kMatrix.length; i++) {
      for(int j = 0; j < kMatrix[0].length; j++) {
        wMatrix[j][i] = kMatrix[j][i];
      }
    }
    // return the W matrix
    return wMatrix;
  }
  
  /**
   * A helper method that builds the rest of the W matrix
   * AKA Steps 3A and 3B of the lab/algo
   * @param wMatrix the W Matrix to finish building
   */
  private void buildRemainingWColumns(String[][] wMatrix) {
    
    // We start at 3 because 1 row is already done
    for(int j = 4; j < wMatrix[0].length; j++) {
      
      // Part 3A of the algorithm, 
      // if column at j isn't a multiple of 4
      if(j % 4 != 0) {
        // We XOR the fourth past and last column with respect
        // to j, as denoted in the following equation:
        //  w(j) = w(j minus 4) xor w(j minus 1) 
        for(int i = 0; i < wMatrix.length; i++) {
          wMatrix[i][j] = xorExtended(wMatrix[i][j - 4],wMatrix[i][j - 1]);
        }
        // No need to keep doing loopy stuff :)
        continue;
      }
      // We are not in a 3A situation,
      // so do 3B of the algorithm (multiple of 4.)
      // Create temporary array
      String[] wTemp = new String[4];
      // now we fill it
      for(int i = 0; i < wMatrix.length; i++) {
        wTemp[i] = wMatrix[i][j-1];
      }
     
      // now we do the shift
      wTemp = shiftArray(wTemp);

      // Transform each of the four bytes in temp W
      for(int i = 0; i < 4; i++) {
        wTemp[i] = aesSBox(Integer.parseInt(wTemp[i],16));
      } 
 
      // Get the Rcon i constant
      String rcon = aesRcon(j / 4);

      // XOR operation using the corresponding round constant 
      wTemp[0] = xorExtended(rcon, wTemp[0]);

      // FINALLY define wMatrix (and XOR)
      for(int i = 0; i < wMatrix.length; i++) {
        wMatrix[i][j] = xorExtended(wMatrix[i][j-4], wTemp[i]);
      }
    }    
  }

  /**
   * A helper method to generate the round keys
   * @param matrix the W matrix to build the round keys from
   * @return the round keys build
   */
  private String[] generateRoundKeys(String[][] matrix) {
    // the round keys to return
    String roundKeysHex[] = new String[11];
    // the reading - a round key is composed of 4 successful readings
    int reading = 0;
    // Until we reach 4 * 11
    while (reading != 44) {
      // store data in a temp matrix to build string later
      String[][] tempMatrix = new String[4][4];
      // loop through
      for(int i = 0; i < matrix.length; i++) {
        for(int j = 0; j < matrix.length; j++) {
          // store
          tempMatrix[j][i] = matrix[j][i+reading];
        }
      }
    // get the hex string
    roundKeysHex[reading / 4] = hexStringBuilder(tempMatrix);
    reading += 4;
    }
    return roundKeysHex;
  }
  
  /**
   * A helper method to perform the XOR function
   * @param fourthPass one of the vaules to xor
   * @param lastColumn the other value to xor
   * @return the value after xop
   */
  private String xorExtended(String fourthPass, String lastColumn){
    String xorString = Integer.toHexString(Integer.parseInt(fourthPass, 16) ^
                                           Integer.parseInt(lastColumn, 16));
    
    return xorString.length() < 2 ? "0" + xorString : xorString;
  }

  /**
   * A helper method to shift the array, cleaner this way
   * @param arrayToShift the array to shift
   * @return the shifted array
   */
  private String[] shiftArray(String[] arrayToShift) {
    return new String[] { arrayToShift[1], arrayToShift[2], 
                          arrayToShift[3], arrayToShift[0] };
  }

  /**
   * A helper method to build a hex string from a matrix
   * @param matrix the matrix to return as a string
   * @return the matrix as a hex string
   */
  private String hexStringBuilder(String[][] matrix) {

    // the one and only way to build a string
    StringBuilder hexKey = new StringBuilder();

    // loopy through the matrix
    for(int i = 0; i < matrix.length; i++) {
      for(int j = 0; j < matrix[0].length; j++) {
        hexKey.append(matrix[j][i].toUpperCase());
      }
    }
    return hexKey.toString();
  }
}