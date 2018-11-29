package com.hycon.HyconUtil;

import static org.junit.Assert.assertEquals;

import java.security.NoSuchAlgorithmException;

import javax.security.auth.login.AccountException;

import org.apache.commons.codec.DecoderException;
import org.junit.Test;


/**
 * Unit test for simple App.
 */
public class AppTest{
	
	static Utils utils = new Utils(); 
	@Test
    public void blake2bByStringTest() throws NoSuchAlgorithmException, DecoderException {
    	String str = "02c4199d83e47650b854e027188eade5378d19c94c13b226f43310fb144bc224af";
    	byte[] result = utils.blake2bHash(str);
    	
    	assertEquals("dafec57d0062e2317f6d0f294366e2a531a891233fd59cfa5f062a0f1018af6a", utils.encodeHexByteArrayToString(result));
    }
	
	@Test
	public void blake2bByByteTest() throws NoSuchAlgorithmException, DecoderException {
    	String str = "02c4199d83e47650b854e027188eade5378d19c94c13b226f43310fb144bc224af";
    	byte[] input = utils.decodeHexStringToByteArray(str);
    	byte[] result = utils.blake2bHash(input);
    	
    	assertEquals("dafec57d0062e2317f6d0f294366e2a531a891233fd59cfa5f062a0f1018af6a", utils.encodeHexByteArrayToString(result));
    }
	
	@Test
	public void base58EncodeTest() throws DecoderException {
		byte[] input = utils.decodeHexStringToByteArray("4366e2a531a891233fd59cfa5f062a0f1018af6a");
		String result = utils.base58Encode(input);
		
		assertEquals("wTsQGpbicAZsXcmSHN8XmcNR9wX", result);
	}
	
	@Test
	public void base58DecodeTest() throws DecoderException, AccountException {
		byte[] result = utils.base58Decode("wTsQGpbicAZsXcmSHN8XmcNR9wX");
		
		assertEquals("4366e2a531a891233fd59cfa5f062a0f1018af6a", utils.encodeHexByteArrayToString(result));
	}
	
	@Test
	public void publicKeyToAddressTest() throws DecoderException, NoSuchAlgorithmException {
		String str = "02c4199d83e47650b854e027188eade5378d19c94c13b226f43310fb144bc224af";
		byte[] input = utils.decodeHexStringToByteArray(str);
		byte[] result = utils.publicKeyToAddress(input);
		
		assertEquals("4366e2a531a891233fd59cfa5f062a0f1018af6a", utils.encodeHexByteArrayToString(result));
	}
	
	@Test
	public void addresssCheckSumTest() throws DecoderException, NoSuchAlgorithmException {
		String str = "4366e2a531a891233fd59cfa5f062a0f1018af6a";
		byte[] input = utils.decodeHexStringToByteArray(str);
		String result = utils.addresssCheckSum(input);
		
		assertEquals("Htw7", result);
	}
	
	@Test
	public void addressToStringTest() throws DecoderException, NoSuchAlgorithmException {
		String str = "4366e2a531a891233fd59cfa5f062a0f1018af6a";
		byte[] input = utils.decodeHexStringToByteArray(str);
		String result = utils.addressToString(input);
		
		assertEquals("HwTsQGpbicAZsXcmSHN8XmcNR9wXHtw7", result);
	}
	
	@Test
	public void addressToByteArrayTest() throws Exception {
		byte[] result = utils.addressToByteArray("HwTsQGpbicAZsXcmSHN8XmcNR9wXHtw7");
		
		assertEquals("4366e2a531a891233fd59cfa5f062a0f1018af6a", utils.encodeHexByteArrayToString(result));
	}
	
	@Test
	public void hyconToFromStringTest() {
		long a = utils.hyconfromString("10.000000001");
		long b = utils.hyconfromString("7.123456789");
		
		long result = a + b;
		
		assertEquals("17.12345679", utils.hyconToString(result));
	}
	
	@Test
	public void signTxTest() throws Exception {
		String[] strArr = utils.signTx("H3N2sCstx81NvvVy3hkrhGsNS43834YWw", "H497fHm8gbPZxaXySKpV17a7beYBF9Ut3", "0.000000001", "0.000000001", 1024, "e09167abb9327bb3748e5dd1b9d3d40832b33eb0b041deeee8e44ff47030a61d");
		
		if(strArr.length > 2) {
			assertEquals("769f69d5a11f634dcb1e8b8f081c6b36b2e37b0a8f1b416314d5a3ceac27cc631e0ec12fd04473e8a168e2556897c55cd7f5e06f3ab917729176aa2e4b002d52", strArr[0]);
			assertEquals("0", strArr[1]);
			assertEquals("fd67de0827ccf8bc957eeb185ba0ea78aa1cd5cad74aea40244361ee7df68e36025aebc4ae6b18628135ea3ef5a70ea3681a7082c44af0899f0f59b50f2707b9", strArr[2]);
			assertEquals("1", strArr[3]);
		} else {
			assertEquals("fd67de0827ccf8bc957eeb185ba0ea78aa1cd5cad74aea40244361ee7df68e36025aebc4ae6b18628135ea3ef5a70ea3681a7082c44af0899f0f59b50f2707b9", strArr[0]);
			assertEquals("1", strArr[1]);
		}
	}
	
	@Test
	public void createWalletTest() throws NoSuchAlgorithmException {
		String[] result = utils.createWallet("ring crime symptom enough erupt lady behave ramp apart settle citizen junk", "");
		
		assertEquals("HwTsQGpbicAZsXcmSHN8XmcNR9wXHtw7", result[0]);
		assertEquals("f35776c86f811d9ab1c66cadc0f503f519bf21898e589c2f26d646e472bfacb2", result[1]);
	}
	
	@Test
	public void createWalletWithPassPhraseTest() throws NoSuchAlgorithmException {
		String[] result = utils.createWallet("way prefer push tooth bench hover orchard brother crumble nothing wink retire", "TREZOR");
		
		assertEquals("H3fFn71jR6G33sAVMASDtLFhrq38h8FQ1", result[0]);
		assertEquals("4c28ef543da7ee616d91ba786ce73ef02cf29818f3cdf5a4639771921a2cf843", result[1]);
	}
}
