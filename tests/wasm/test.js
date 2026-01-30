// Copyright (c) 2024 Keystore-RS Contributors
// SPDX-License-Identifier: MIT

/**
 * WASM Runtime Tests for jks library with PKCS12 support
 * Tests the core functionality using Node.js and wasm-pack
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
  log(`  ✓ ${message}`, colors.green);
}

function error(message) {
  log(`  ✗ ${message}`, colors.red);
}

function info(message) {
  log(`  ${message}`, colors.blue);
}

async function runTests() {
  log('JKS WASM Runtime Tests (with PKCS12 support)', colors.blue);
  log('=============================================', colors.blue);
  log('');

  let passed = 0;
  let failed = 0;

  try {
    // Load the wasm-pack generated module
    const wasmPkgPath = path.join(__dirname, 'pkg');
    if (!fs.existsSync(wasmPkgPath)) {
      error('WASM package not found!');
      log('  Build with: cd tests/wasm && wasm-pack build --target nodejs', colors.yellow);
      process.exit(1);
    }

    const wasm = require('./pkg/jks_wasm_test.js');

    // Test 1: Basic operations
    log('Test 1: test_basic_operations()');
    try {
      const result = wasm.test_basic_operations();
      success(result);
      passed++;
    } catch (e) {
      error(`Failed: ${e}`);
      failed++;
    }
    log('');

    // Test 2: Load JKS file
    const jksPath = '/tmp/my-release-key.jks';
    if (fs.existsSync(jksPath)) {
      log('Test 2: Load JKS file from keytool');
      try {
        const jksData = fs.readFileSync(jksPath);
        const result = wasm.load_jks(jksData, 'android');
        const parsed = JSON.parse(result);
        success(`Loaded JKS with ${parsed.count} entries`);
        info(`  Aliases: ${parsed.aliases.join(', ')}`);
        passed++;
      } catch (e) {
        error(`Failed: ${e}`);
        failed++;
      }
      log('');
    } else {
      log('Test 2: Load JKS file - SKIPPED (file not found)', colors.yellow);
      info(`  Create with: keytool -genkey -v -keystore ${jksPath} -storetype JKS -alias agusibrahim -keyalg RSA -keysize 2048 -validity 10000 -storepass android -keypass android`);
      log('');
    }

    // Test 3: Load PKCS12 (.keystore) file
    const p12Path = '/tmp/my-release-key.keystore';
    const testP12Path = '/tmp/test.p12';

    // Try with Android keystore first
    if (fs.existsSync(p12Path)) {
      log('Test 3: Load PKCS12 (.keystore) file');
      try {
        const p12Data = fs.readFileSync(p12Path);
        const result = wasm.load_pkcs12(p12Data, 'android');
        const parsed = JSON.parse(result);
        success(`Loaded PKCS12 with ${parsed.count} entries`);
        info(`  Aliases: ${parsed.aliases.join(', ')}`);
        passed++;

        // Test 3b: Get private key info
        if (parsed.aliases.length > 0) {
          log('Test 3b: Get PKCS12 private key info');
          try {
            const keyInfo = wasm.get_pkcs12_private_key_info(p12Data, 'android', parsed.aliases[0]);
            const keyParsed = JSON.parse(keyInfo);
            success(`Private key: ${keyParsed.privateKeyLength} bytes, ${keyParsed.certChainLength} certs`);
            passed++;
          } catch (e) {
            error(`Failed: ${e}`);
            failed++;
          }
        }
      } catch (e) {
        // Try with test.p12 using changeit password
        log('  Android keystore failed, trying test.p12...', colors.yellow);
        if (fs.existsSync(testP12Path)) {
          try {
            const p12Data = fs.readFileSync(testP12Path);
            const result = wasm.load_pkcs12(p12Data, 'changeit');
            const parsed = JSON.parse(result);
            success(`Loaded test PKCS12 with ${parsed.count} entries`);
            info(`  Aliases: ${parsed.aliases.join(', ')}`);
            passed++;
          } catch (e2) {
            error(`Failed: ${e2}`);
            failed++;
          }
        } else {
          error(`Failed: ${e}`);
          failed++;
        }
      }
      log('');
    } else if (fs.existsSync(testP12Path)) {
      log('Test 3: Load test PKCS12 file');
      try {
        const p12Data = fs.readFileSync(testP12Path);
        const result = wasm.load_pkcs12(p12Data, 'changeit');
        const parsed = JSON.parse(result);
        success(`Loaded PKCS12 with ${parsed.count} entries`);
        info(`  Aliases: ${parsed.aliases.join(', ')}`);
        passed++;
      } catch (e) {
        error(`Failed: ${e}`);
        failed++;
      }
      log('');
    } else {
      log('Test 3: Load PKCS12 file - SKIPPED (file not found)', colors.yellow);
      info(`  Create with: keytool -genkey -v -keystore ${p12Path} -alias agusibrahim -keyalg RSA -keysize 2048 -validity 10000 -storepass android -keypass android`);
      log('');
    }

    // Test 4: Auto-detect with JKS
    if (fs.existsSync(jksPath)) {
      log('Test 4: Auto-detect JKS format');
      try {
        const jksData = fs.readFileSync(jksPath);
        const result = wasm.load_auto_detect(jksData, 'android');
        const parsed = JSON.parse(result);
        success(`Auto-detected JKS with ${parsed.count} entries`);
        passed++;
      } catch (e) {
        error(`Failed: ${e}`);
        failed++;
      }
      log('');
    }

    // Test 5: Auto-detect with PKCS12
    if (fs.existsSync(p12Path)) {
      log('Test 5: Auto-detect PKCS12 format');
      try {
        const p12Data = fs.readFileSync(p12Path);
        const result = wasm.load_auto_detect(p12Data, 'android');
        const parsed = JSON.parse(result);
        success(`Auto-detected PKCS12 with ${parsed.count} entries`);
        passed++;
      } catch (e) {
        error(`Failed: ${e}`);
        failed++;
      }
      log('');
    }

    // Test 6: Get JKS private key info with decryption
    if (fs.existsSync(jksPath)) {
      log('Test 6: Get JKS private key info (with decryption)');
      try {
        const jksData = fs.readFileSync(jksPath);
        const keyInfo = wasm.get_private_key_info(jksData, 'android', 'agusibrahim');
        const keyParsed = JSON.parse(keyInfo);
        success(`Private key: ${keyParsed.privateKeyLength} bytes, ${keyParsed.certChainLength} certs`);
        passed++;
      } catch (e) {
        error(`Failed: ${e}`);
        failed++;
      }
      log('');
    }

    // Summary
    log('=============================================', colors.blue);
    log(`Results: ${passed} passed, ${failed} failed`, passed > 0 && failed === 0 ? colors.green : colors.red);

    if (failed === 0) {
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
