package com.hycon.HyconUtil;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.bitcoinj.core.AddressFormatException;
import org.bitcoinj.core.Base58;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDKeyDerivation;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Sign;
import org.web3j.crypto.Sign.SignatureData;

import com.google.protobuf.ByteString;
import com.hycon.HyconUtil.generator.MnemonicGenerator;
import com.hycon.HyconUtil.mnemonic.ChineseSimplified;
import com.hycon.HyconUtil.mnemonic.ChineseTraditional;
import com.hycon.HyconUtil.mnemonic.English;
import com.hycon.HyconUtil.mnemonic.French;
import com.hycon.HyconUtil.mnemonic.Italian;
import com.hycon.HyconUtil.mnemonic.Japanese;
import com.hycon.HyconUtil.mnemonic.Korean;
import com.hycon.HyconUtil.mnemonic.Spanish;
import com.hycon.proto.TxOuterClass;
import com.hycon.proto.TxOuterClass.Tx;
import com.rfksystems.blake2b.Blake2b;
import com.rfksystems.blake2b.security.Blake2bProvider;

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
	
	public String[] signTx(String fromAddress, String toAddress, String amount, String minerFee, int nonce, String privatekey, String networkId) throws Exception {
		byte[] from = addressToByteArray(fromAddress);
		byte[] to = addressToByteArray(toAddress);
		
		Tx.Builder txBuilder = Tx.newBuilder();
		txBuilder.setFrom(ByteString.copyFrom(from));
		txBuilder.setTo(ByteString.copyFrom(to));
		txBuilder.setAmount(hyconfromString(amount));
		txBuilder.setFee(hyconfromString(minerFee));
		txBuilder.setNonce(nonce);
		
		Tx.Builder newTxBuilder = Tx.newBuilder(txBuilder.build());
		newTxBuilder.setNetworkid(networkId);
		TxOuterClass.Tx newTx = newTxBuilder.build();
		byte[] newTxData = newTx.toByteArray();
		byte[] newTxHash = blake2bHash(newTxData);
		ECKeyPair ecKeyPair = ECKeyPair.create(decodeHexStringToByteArray(privatekey));
		SignatureData signatureData = Sign.signMessage(newTxHash, ecKeyPair, false);
		String signature = encodeHexByteArrayToString(signatureData.getR()) + encodeHexByteArrayToString(signatureData.getS());
		String recovery = String.valueOf(signatureData.getV() - 27);
		
		String[] result = new String[2];

		result[0] = signature;
		result[1] = recovery;
		
		return result;
	}
	
	public String getMnemonic(String language) throws IOException {
		
		String[] wordList = getBip39WordList(language);

        return MnemonicGenerator.generateMnemonic(wordList);
	}
	
	public String[] createWallet(String mnemonic, String passphrase) throws NoSuchAlgorithmException {

		byte[] seed = MnemonicGenerator.generateSeed(mnemonic, passphrase);
		DeterministicKey masterKey = HDKeyDerivation.createMasterPrivateKey(seed);
		ECKey finalKeyPair = fromBIP44HDPath(masterKey, 0);
		
		String[] result = new String[2]; // 0 : address, 1 : private key
		
		result[0] = addressToString(publicKeyToAddress(finalKeyPair.getPubKey()));
		result[1] = encodeHexByteArrayToString(finalKeyPair.getPrivKeyBytes());
		
		return result;
		
	}
	
	public String createHDWallet(String mnemonic, String passphrase) throws Exception {
		byte[] seed = MnemonicGenerator.generateSeed(mnemonic, passphrase);
		DeterministicKey masterKey = HDKeyDerivation.createMasterPrivateKey(seed);
		
		if(!masterKey.hasPrivKey()) {
			throw new Exception("masterKey does not have Extended PrivateKey");
		}
		
		return masterKey.serializePrivB58(NetworkParameters.fromID(NetworkParameters.ID_MAINNET));
	}
	
	public String[] getWalletFromExtKey(String privateExtendedKey, int index) throws DecoderException, NoSuchAlgorithmException {
		DeterministicKey masterKey = DeterministicKey.deserializeB58(privateExtendedKey, NetworkParameters.fromID(NetworkParameters.ID_MAINNET));
		
		ECKey finalKeyPair = fromBIP44HDPath(masterKey, index);
		
		String[] result = new String[2]; // 0 : address, 1 : private key
		
		result[0] = addressToString(publicKeyToAddress(finalKeyPair.getPubKey()));
		result[1] = encodeHexByteArrayToString(finalKeyPair.getPrivKeyBytes());
		
		return result;
		
	}
	
	private String[] getBip39WordList(String language) {
		if(language.equals("englise")) {
			return English.words;
		} else if(language.equals("korean")) {
			return Korean.words;
		} else if(language.equals("chinese_simplified")) {
			return ChineseSimplified.words;
		} else if(language.equals("chinese_traditional")) {
			return ChineseTraditional.words;
		} else if(language.equals("chinese")) {
			throw new Error("Did you mean chinese_simplified or chinese_traditional?");
		} else if(language.equals("japanese")) {
			return Japanese.words;
		} else if(language.equals("french")) {
			return French.words;
		} else if(language.equals("spanish")) {
			return Spanish.words;
		} else if(language.equals("italian")) {
			return Italian.words;
		} else {
			return English.words;
		}
	}
	
	private ECKey fromBIP44HDPath (DeterministicKey master, int accountIndex) {
        DeterministicKey purposeKey = HDKeyDerivation.deriveChildKey(master, 44 | ChildNumber.HARDENED_BIT) ;
        DeterministicKey rootKey = HDKeyDerivation.deriveChildKey(purposeKey, 1397 | ChildNumber.HARDENED_BIT);
        DeterministicKey accountKey = HDKeyDerivation.deriveChildKey(rootKey, 0 | ChildNumber.HARDENED_BIT) ;
        DeterministicKey changeKey = HDKeyDerivation.deriveChildKey(accountKey, 0) ;
        DeterministicKey addressKey = HDKeyDerivation.deriveChildKey(changeKey, accountIndex) ;
		
        return ECKey.fromPrivate(addressKey.getPrivKeyBytes());
    }
}
