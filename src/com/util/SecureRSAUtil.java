package com.util;

/*******************************************************
 * Description:RSA 工具类<br/>
 ********************************************************/

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Date;

import javax.crypto.Cipher;

import org.apache.commons.io.IOUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.time.DateFormatUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class SecureRSAUtil {

	/**
	 * 算法名称
	 */
	private static final String ALGORITHOM = "RSA";
	/**
	 * 保存生成的密钥对的文件名称。
	 */
	private static final String RSA_PAIR_FILENAME = "/_PAIR_RSA_ZC.txt";
	/**
	 * 密钥大小
	 */
	private static final int KEY_SIZE = 1024;
	/**
	 * 默认的安全服务提供者
	 */
	private static final Provider DEFAULT_PROVIDER = new BouncyCastleProvider();
	/**
	 * 密钥对生成器
	 */
	private static KeyPairGenerator keyPairGen = null;
	private static KeyFactory keyFactory = null;
	/**
	 * 缓存的密钥对。
	 */
	private static KeyPair oneKeyPair = null;

	private static File rsaPairFile = null;

	/*****************************************
	 * Description：静态方法，仅执行一次<br/>
	 * 
	 * @return
	 *****************************************/
	static {
		try {
			keyPairGen = KeyPairGenerator.getInstance(ALGORITHOM, DEFAULT_PROVIDER);
			keyFactory = KeyFactory.getInstance(ALGORITHOM, DEFAULT_PROVIDER);
		} catch (NoSuchAlgorithmException ex) {
		}
		rsaPairFile = new File(getRSAPairFilePath());
	}

	private SecureRSAUtil() {
	}

	/*****************************************
	 * Description：生成并返回RSA密钥对<br/>
	 * 
	 * @return
	 *****************************************/
	private static synchronized KeyPair generateKeyPair() {
		keyPairGen.initialize(KEY_SIZE, new SecureRandom(DateFormatUtils.format(new Date(), "yyyyMMdd").getBytes()));
		oneKeyPair = keyPairGen.generateKeyPair();
		saveKeyPair(oneKeyPair);
		return oneKeyPair;
	}

	/*****************************************
	 * Description：返回生成/读取的密钥对文件的路径<br/>
	 * 
	 * @return
	 *****************************************/
	private static String getRSAPairFilePath() {
		String urlPath = "D:\\RSAFILE\\";
		// MpbSecureRSAUtil.class.getResource("/").getPath();
		return (new File(urlPath) + RSA_PAIR_FILENAME);
		// (new File(urlPath).getParent() + RSA_PAIR_FILENAME);
	}

	/*****************************************
	 * Description：若需要创建新的密钥对文件<br/>
	 * 
	 * @return
	 *****************************************/
	private static boolean isCreateKeyPairFile() {
		// 是否创建新的密钥对文件
		boolean createNewKeyPair = false;
		if (!rsaPairFile.exists() || rsaPairFile.isDirectory()) {
			System.out.println("重新生成密钥对文件");
			createNewKeyPair = true;
		}
		return createNewKeyPair;
	}

	/*****************************************
	 * Description：将指定的RSA密钥对以文件形式保存<br/>
	 * 
	 * @param keyPaire
	 *            要保存的密钥对。
	 * @return
	 *****************************************/
	private static void saveKeyPair(KeyPair keyPair) {
		FileOutputStream fos = null;
		ObjectOutputStream oos = null;
		try {
			fos = FileUtils.openOutputStream(rsaPairFile);
			oos = new ObjectOutputStream(fos);
			oos.writeObject(keyPair);
		} catch (Exception ex) {
			ex.printStackTrace();
		} finally {
			IOUtils.closeQuietly(oos);
			IOUtils.closeQuietly(fos);
		}
	}

	/*****************************************
	 * Description：返回RSA密钥对。<br/>
	 * 
	 * @param keyPair
	 *            要保存的密钥对。
	 * @return
	 *****************************************/
	public static KeyPair getKeyPair() {
		// 首先判断是否需要重新生成新的密钥对文件
		if (isCreateKeyPairFile()) {
			// 直接强制生成密钥对文件，并存入缓存。
			return generateKeyPair();
		}
		if (oneKeyPair != null) {
			return oneKeyPair;
		}
		return readKeyPair();
	}

	/*****************************************
	 * Description：同步读出保存的密钥对<br/>
	 * 
	 * @return
	 *****************************************/
	private static KeyPair readKeyPair() {
		FileInputStream fis = null;
		ObjectInputStream ois = null;
		try {
			fis = FileUtils.openInputStream(rsaPairFile);
			ois = new ObjectInputStream(fis);
			oneKeyPair = (KeyPair) ois.readObject();
			return oneKeyPair;
		} catch (Exception ex) {
			ex.printStackTrace();
		} finally {
			IOUtils.closeQuietly(ois);
			IOUtils.closeQuietly(fis);
		}
		return null;
	}

	/*****************************************
	 * Description：根据给定的系数和专用指数构造一个RSA专用的公钥对象<br/>
	 * 
	 * @param modulus
	 *            系数。
	 * @param publicExponent
	 *            专用指数。
	 * @return RSA专用公钥对象。。
	 *****************************************/
	public static RSAPublicKey generateRSAPublicKey(byte[] modulus, byte[] publicExponent) {
		RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(new BigInteger(modulus), new BigInteger(publicExponent));
		try {
			return (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
		} catch (InvalidKeySpecException ex) {
		} catch (NullPointerException ex) {
		}
		return null;
	}

	/*****************************************
	 * Description：根据给定的系数和专用指数构造一个RSA专用的私钥对象<br/>
	 * 
	 * @param modulus
	 *            系数。
	 * @param privateExponent
	 *            专用指数。
	 * @return RSA专用私钥对象。
	 ******************************************/
	public static RSAPrivateKey generateRSAPrivateKey(byte[] modulus, byte[] privateExponent) {
		RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(new BigInteger(modulus),
				new BigInteger(privateExponent));
		try {
			return (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);
		} catch (InvalidKeySpecException ex) {
		} catch (NullPointerException ex) {
		}
		return null;
	}

	/*****************************************
	 * Description：根据给定的16进制系数和专用指数字符串构造一个RSA专用的私钥对象<br/>
	 * 
	 * @param modulus
	 *            系数。
	 * @param privateExponent
	 *            专用指数。
	 * @return RSA专用私钥对象。
	 ******************************************/
	public static RSAPrivateKey getRSAPrivateKey(String hexModulus, String hexPrivateExponent) {
		if (StringUtils.isBlank(hexModulus) || StringUtils.isBlank(hexPrivateExponent)) {
			return null;
		}
		byte[] modulus = null;
		byte[] privateExponent = null;
		try {
			modulus = Hex.decodeHex(hexModulus.toCharArray());
			privateExponent = Hex.decodeHex(hexPrivateExponent.toCharArray());
		} catch (DecoderException ex) {
		}
		if (modulus != null && privateExponent != null) {
			return generateRSAPrivateKey(modulus, privateExponent);
		}
		return null;
	}

	/*****************************************
	 * Description：根据给定的16进制系数和专用指数字符串构造一个RSA专用的公钥对象<br/>
	 * 
	 * @param modulus
	 *            系数。
	 * @param privateExponent
	 *            专用指数。
	 * @return RSA专用公钥对象。
	 ******************************************/
	public static RSAPublicKey getRSAPublidKey(String hexModulus, String hexPublicExponent) {
		if (StringUtils.isBlank(hexModulus) || StringUtils.isBlank(hexPublicExponent)) {
			return null;
		}
		byte[] modulus = null;
		byte[] publicExponent = null;
		try {
			modulus = Hex.decodeHex(hexModulus.toCharArray());
			publicExponent = Hex.decodeHex(hexPublicExponent.toCharArray());
		} catch (DecoderException ex) {
		}
		if (modulus != null && publicExponent != null) {
			return generateRSAPublicKey(modulus, publicExponent);
		}
		return null;
	}

	/*****************************************
	 * Description：使用指定的公钥加密数据<br/>
	 * 
	 * @param publicKey
	 *            给定的公钥。
	 * @param data
	 *            要加密的数据。
	 * @return 加密后的数据。
	 *******************************************/
	public static byte[] encrypt(PublicKey publicKey, byte[] data) throws Exception {
		Cipher ci = Cipher.getInstance(ALGORITHOM, DEFAULT_PROVIDER);
		ci.init(Cipher.ENCRYPT_MODE, publicKey);
		return ci.doFinal(data);
	}

	/*****************************************
	 * Description：使用指定的私钥解密数据<br/>
	 * 
	 * @param privateKey
	 *            给定的私钥。
	 * @param data
	 *            要解密的数据。
	 * @return 原数据。
	 *******************************************/
	public static byte[] decrypt(PrivateKey privateKey, byte[] data) throws Exception {
		Cipher ci = Cipher.getInstance(ALGORITHOM, DEFAULT_PROVIDER);
		ci.init(Cipher.DECRYPT_MODE, privateKey);
		return ci.doFinal(data);
	}

	/*****************************************
	 * Description：使用给定的公钥加密给定的字符串<br/>
	 * 
	 * @param publicKey
	 *            给定的公钥。
	 * @param plaintext
	 *            字符串。
	 * @return 给定字符串的密文。
	 *******************************************/
	public static String encryptString(PublicKey publicKey, String plaintext) {
		if (publicKey == null || plaintext == null) {
			return null;
		}
		byte[] data = plaintext.getBytes();
		try {
			byte[] en_data = encrypt(publicKey, data);
			return new String(Hex.encodeHex(en_data));
		} catch (Exception ex) {
		}
		return null;
	}

	/*****************************************
	 * Description：使用默认的公钥加密给定的字符串<br/>
	 * 
	 * @param plaintext
	 *            字符串。
	 * @return 给定字符串的密文。
	 *******************************************/
	public static String encryptString(String plaintext) {
		if (plaintext == null) {
			return null;
		}
		byte[] data = plaintext.getBytes();
		KeyPair keyPair = getKeyPair();
		try {
			byte[] en_data = encrypt((RSAPublicKey) keyPair.getPublic(), data);
			return new String(Hex.encodeHex(en_data));
		} catch (NullPointerException ex) {
		} catch (Exception ex) {
		}
		return null;
	}

	/*****************************************
	 * Description：使用给定的私钥解密给定的字符串<br/>
	 * 
	 * @param privateKey
	 *            给定的私钥。
	 * @param encrypttext
	 *            密文。
	 * @return 原文字符串。
	 *******************************************/
	public static String decryptString(PrivateKey privateKey, String encrypttext) {
		if (privateKey == null || StringUtils.isBlank(encrypttext)) {
			return null;
		}
		try {
			byte[] en_data = Hex.decodeHex(encrypttext.toCharArray());
			byte[] data = decrypt(privateKey, en_data);
			return new String(data);
		} catch (Exception ex) {
		}
		return null;
	}

	/*****************************************
	 * Description：使用默认的私钥解密给定的字符串<br/>
	 * 
	 * @param encrypttext
	 *            密文。
	 * @return 原文字符串。
	 *******************************************/
	public static String decryptString(String encrypttext) {
		if (StringUtils.isBlank(encrypttext)) {
			return null;
		}
		KeyPair keyPair = getKeyPair();
		try {
			byte[] en_data = Hex.decodeHex(encrypttext.toCharArray());
			byte[] data = decrypt((RSAPrivateKey) keyPair.getPrivate(), en_data);
			return new String(data);
		} catch (NullPointerException ex) {
		} catch (Exception ex) {
		}
		return null;
	}

	/*****************************************
	 * Description：使用默认的私钥解密由JS加密（使用此类提供的公钥加密）的字符串<br/>
	 * 
	 * @param encrypttext
	 *            密文。
	 * @return {@code encrypttext} 的原文字符串。
	 *******************************************/
	public static String decryptStringByJs(String encrypttext) {
		String text = decryptString(encrypttext);
		if (text == null) {
			return null;
		}
		return StringUtils.reverse(text);
	}

	/*****************************************
	 * Description：返回已初始化的默认的公钥<br/>
	 * 
	 * @param
	 * @return
	 *******************************************/
	public static RSAPublicKey getDefaultPublicKey() {
		KeyPair keyPair = getKeyPair();
		if (keyPair != null) {
			return (RSAPublicKey) keyPair.getPublic();
		}
		return null;
	}

	/*****************************************
	 * Description：返回已初始化的默认的私钥<br/>
	 * 
	 * @param
	 * @return
	 *******************************************/
	public static RSAPrivateKey getDefaultPrivateKey() {
		KeyPair keyPair = getKeyPair();
		if (keyPair != null) {
			return (RSAPrivateKey) keyPair.getPrivate();
		}
		return null;
	}

	/**
	 * BCD转字符串
	 */
	public static String bcd2Str(byte[] bytes) {
		char temp[] = new char[bytes.length * 2], val;

		for (int i = 0; i < bytes.length; i++) {
			val = (char) (((bytes[i] & 0xf0) >> 4) & 0x0f);
			temp[i * 2] = (char) (val > 9 ? val + 'A' - 10 : val + '0');

			val = (char) (bytes[i] & 0x0f);
			temp[i * 2 + 1] = (char) (val > 9 ? val + 'A' - 10 : val + '0');
		}
		return new String(temp);
	}

	/**
	 * 拆分字符串
	 */
	public static String[] splitString(String string, int len) {
		int x = string.length() / len;
		int y = string.length() % len;
		int z = 0;
		if (y != 0) {
			z = 1;
		}
		String[] strings = new String[x + z];
		String str = "";
		for (int i = 0; i < x + z; i++) {
			if (i == x + z - 1 && y != 0) {
				str = string.substring(i * len, i * len + y);
			} else {
				str = string.substring(i * len, i * len + len);
			}
			strings[i] = str;
		}
		return strings;
	}

	/**
	 * 拆分数组
	 */
	public static byte[][] splitArray(byte[] data, int len) {
		int x = data.length / len;
		int y = data.length % len;
		int z = 0;
		if (y != 0) {
			z = 1;
		}
		byte[][] arrays = new byte[x + z][];
		byte[] arr;
		for (int i = 0; i < x + z; i++) {
			arr = new byte[len];
			if (i == x + z - 1 && y != 0) {
				System.arraycopy(data, i * len, arr, 0, y);
			} else {
				System.arraycopy(data, i * len, arr, 0, len);
			}
			arrays[i] = arr;
		}
		return arrays;
	}

}
