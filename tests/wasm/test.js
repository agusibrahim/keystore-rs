// Copyright (c) 2024 Keystore-RS Contributors
// SPDX-License-Identifier: MIT

/**
 * WASM Runtime Tests for jks library
 * Tests the core functionality using Node.js WebAssembly API
 */

const fs = require('fs');
const path = require('path');

// ANSI color codes for terminal output
const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[36m',
};

function log(message, color = colors.reset) {
  console.log(`${color}${message}${colors.reset}`);
}

function success(message) {
  log(`  ${message}`, colors.green);
}

function error(message) {
  log(`  ${message}`, colors.red);
}

function info(message) {
  log(`  ${message}`, colors.blue);
}

async function loadWasm() {
  const wasmPath = path.join(__dirname, 'target/wasm32-unknown-unknown/release/jks_wasm_test.wasm');

  if (!fs.existsSync(wasmPath)) {
    log('', colors.reset);
    error('WASM file not found!');
    log(`  Expected path: ${wasmPath}`, colors.yellow);
    log('', colors.reset);
    log('  Build the WASM module first:', colors.blue);
    log('  cargo build --target wasm32-unknown-unknown --manifest-path=tests/wasm/Cargo.toml --release', colors.yellow);
    log('', colors.reset);
    process.exit(1);
  }

  const wasmBuffer = fs.readFileSync(wasmPath);
  const module = await WebAssembly.compile(wasmBuffer);
  const instance = await WebAssembly.instantiate(module, {});
  return instance.exports;
}

async function runTests() {
  log('JKS WASM Runtime Tests', colors.blue);
  log('=======================', colors.blue);
  log('');

  try {
    const exports = await loadWasm();

    // Test 1: test_create_trusted_cert
    log('Running: test_create_trusted_cert()');
    const result1 = exports.test_create_trusted_cert();
    if (result1 === 0) {
      success('PASSED - Trusted certificate entry created successfully');
    } else {
      error(`FAILED - Expected 0, got ${result1}`);
    }
    log('');

    // Test 2: test_alias_count
    log('Running: test_alias_count()');
    const result2 = exports.test_alias_count();
    if (result2 === 0) {
      success('PASSED - Alias count is 0 (empty keystore)');
    } else {
      error(`FAILED - Expected 0, got ${result2}`);
    }
    log('');

    // Test 3: test_all
    log('Running: test_all()');
    const result3 = exports.test_all();
    if (result3 === 0) {
      success('PASSED - All operations completed successfully');
    } else {
      error(`FAILED - Error code: ${result3}`);
    }
    log('');

    // Summary
    const allPassed = result1 === 0 && result2 === 0 && result3 === 0;
    log('=======================', colors.blue);
    if (allPassed) {
      log('All tests PASSED!', colors.green);
      process.exit(0);
    } else {
      log('Some tests FAILED!', colors.red);
      process.exit(1);
    }

  } catch (err) {
    error(`Error: ${err.message}`);
    log('', colors.reset);
    log(err.stack, colors.red);
    process.exit(1);
  }
}

// Run tests
runTests();
