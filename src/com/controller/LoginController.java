package com.controller;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Hex;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.util.SecureRSAUtil;

import net.sf.json.JSONObject;

@Controller
@RequestMapping("/login")
public class LoginController {

	@RequestMapping(value = "/getPairKey", method = RequestMethod.GET)
	@ResponseBody
	public String getKey(@RequestParam("callback") String callback) throws Exception {
		RSAPublicKey publicKey = SecureRSAUtil.getDefaultPublicKey();

		Map<String, String> map = new HashMap<String, String>();
		map.put("modul", new String(Hex.encodeHex(publicKey.getModulus().toByteArray())));
		map.put("exponent", new String(Hex.encodeHex(publicKey.getPublicExponent().toByteArray())));

		JSONObject jsonObject = JSONObject.fromObject(map);
		return callback + "(" + jsonObject + ")";
	}

	@RequestMapping(value = "/check", method = RequestMethod.POST)
	public void checkLogin(@RequestParam("username") String username, @RequestParam("password") String password)
			throws Exception {
		
		String psw = SecureRSAUtil.decryptString(password);

		System.out.println(username);
		System.out.println(new StringBuffer(psw).reverse().toString());
	}
}
