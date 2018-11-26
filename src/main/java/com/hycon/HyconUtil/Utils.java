package com.hycon.HyconUtil;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Sign;
import org.web3j.crypto.Sign.SignatureData;

import com.google.bitcoin.core.AddressFormatException;
import com.google.bitcoin.core.Base58;
import com.google.protobuf.ByteString;
import com.hycon.proto.TxOuterClass;
import com.hycon.proto.TxOuterClass.Tx;
import com.rfksystems.blake2b.*;
import com.rfksystems.blake2b.security.Blake2bProvider;

import java.security.Security;

public class Utils {
	
	public Utils(){
		Security.addProvider(new Blake2bProvider());
	}
	
	public String encodeHexByteArrayToString(byte[] ob) {
		return Hex.encodeHexString(ob);
	}
	
	public byte[] decodeHexStringToByteArray(String str) throws DecoderException {
		return Hex.decodeHex(str.toCharArray());
	}
	
	public byte[] blake2bHash(byte[] ob) throws NoSuchAlgorithmException {
		
		
		return MessageDigest.getInstance(Blake2b.BLAKE2_B_256).digest(ob);
	}
	
	public byte[] blake2bHash(String ob) throws NoSuchAlgorithmException, DecoderException {
		
		
		return MessageDigest.getInstance(Blake2b.BLAKE2_B_256).digest(Hex.decodeHex(ob.toCharArray()));
	}
	
	public String base58Encode(byte[] ob) {
		return Base58.encode(ob);
	}
	
	public byte[] base58Decode(String ob) throws AddressFormatException {
		return Base58.decode(ob);
	}
	
	public byte[] publicKeyToAddress(byte[] publicKey) throws NoSuchAlgorithmException {
		byte[] hash = blake2bHash(publicKey);
		byte[] result = new byte[20];
		for(int i=12; i<32; ++i) {
			result[i-12] = hash[i];
		}
		
		return result;
	}
	
	public String addresssCheckSum(byte[] arr) throws NoSuchAlgorithmException {
		byte[] hash = blake2bHash(arr);
		String str = base58Encode(hash);
		str = str.substring(0, 4);
		
		return str;
	}
	
	public String addressToString(byte[] publicKey) throws NoSuchAlgorithmException {
		return "H" + base58Encode(publicKey) + addresssCheckSum(publicKey);
	}
	
	public byte[] addressToByteArray(String address) throws Exception {
		if(address.charAt(0) != 'H') {
			throw new Exception("Address is invalid. Expected address to start with 'H'");
		}
		
		String checkSum = address.substring(address.length() - 4, address.length());
		address = address.substring(1, address.length() - 4);
		byte[] out = base58Decode(address);
		
		if(out.length != 20) {
			throw new Exception("Address must be 20 bytes long");
		}
		
		String expectChecksum = addresssCheckSum(out);
		if(!expectChecksum.equals(checkSum)) {
			throw new Exception("Address hash invalid checksum " + checkSum + " expected " + expectChecksum);
		}
		
		return out;
		
	}
	
	public long hyconfromString(String val) {
		if(val.equals("") || val == null) {
			return Long.valueOf("0");
		}
		
		if(val.toCharArray()[val.length() - 1] == '.') {
			val += "0";
		}
		
		String[] arr = val.split("\\.");
		
		long hycon = Long.valueOf("0");
		hycon = hycon + (Long.valueOf(arr[0]) * ((long)Math.pow(10, 9)));
		
		if(arr.length > 1) {
			arr[1] = arr[1].length() > 9 ? arr[1].substring(0, 9) : arr[1];
			long subCon = Long.valueOf(arr[1]) * ((long) Math.pow(10, 9 - arr[1].length()));
			hycon = hycon + subCon;
		}
		
		return hycon;
	}
	
	public String hyconToString(long val) {
		long integer = val / Long.valueOf("1000000000");
		long sub = val % Long.valueOf("1000000000");
		
		if(sub == 0) {
			return String.valueOf(integer);
		}
		
		String decimals = String.valueOf(sub);
		while(decimals.length() < 9) {
			decimals = "0" + decimals;
		}
		
		while(decimals.charAt(decimals.length() - 1) == '0') {
			decimals = decimals.substring(0, decimals.length() - 1);
		}
		
		return String.valueOf(integer) + "." + decimals;
	}
	
	public String[] signTx(String fromAddress, String toAddress, String amount, String minerFee, int nonce, String privatekey) throws Exception {
		byte[] from = addressToByteArray(fromAddress);
		byte[] to = addressToByteArray(toAddress);
		
		Tx.Builder txBuilder = Tx.newBuilder();
		txBuilder.setFrom(ByteString.copyFrom(from));
		txBuilder.setTo(ByteString.copyFrom(to));
		txBuilder.setAmount(hyconfromString(amount));
		txBuilder.setFee(hyconfromString(minerFee));
		txBuilder.setNonce(nonce);
		
		Tx.Builder newTxBuilder = Tx.newBuilder(txBuilder.build());
		newTxBuilder.setNetworkid("hycon");
		TxOuterClass.Tx newTx = newTxBuilder.build();
		byte[] newTxData = newTx.toByteArray();
		byte[] newTxHash = blake2bHash(newTxData);
		ECKeyPair ecKeyPair = ECKeyPair.create(decodeHexStringToByteArray(privatekey));
		SignatureData newSignatureData = Sign.signMessage(newTxHash, ecKeyPair, false);
		String newSignature = encodeHexByteArrayToString(newSignatureData.getR()) + encodeHexByteArrayToString(newSignatureData.getS());
		String newRecovery = String.valueOf(newSignatureData.getV() - 27);
		
		String[] result = new String[4];
		int index = 0;
		
		if(System.currentTimeMillis() <= Long.valueOf("1544108400000")) {
			TxOuterClass.Tx tx = txBuilder.build();
			byte[] txData = tx.toByteArray();
			byte[] txhash = blake2bHash(txData);
			SignatureData signatureData = Sign.signMessage(txhash, ecKeyPair, false);
			
			String signature = encodeHexByteArrayToString(signatureData.getR()) + encodeHexByteArrayToString(signatureData.getS());
			String recovery = String.valueOf(signatureData.getV() - 27);
			
			result[index++] = signature;
			result[index++] = recovery;
			result[index++] = newSignature;
			result[index++] = newRecovery;
		} else {
			result[index++] = newSignature;
			result[index++] = newRecovery;
		}
		
		return result;
	}
}
