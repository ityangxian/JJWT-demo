package com.tbb.jjwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;

import java.security.Key;
import java.security.KeyPair;
import java.util.Date;
import java.util.UUID;

/**
 *
 */
public class Main {


    public static void main(String[] args) {

        /**
         *  获取key的三种方式:
         *
         *  1. hmacShaKeyFor()
         *      a. 采用固定的key加密;
         *      b. 不同的加密算法有不同的字节长度要求(不低于32个字节);
         *      c. 通过getEncoded() 获取key的字节数组;
         *
         *  1. secretKeyFor()
         *      a. 加密算法采用 HS256 或 HS384 或 HS512;
         *      b. 得到一个随机加密的key;
         *      c. jwt 编码与解码需要用同一个key(对称加密)
         *
         *  2. keyPairFor()
         *      a. 加密算法采用 RS256 或 RS384，RS512，PS256，PS384，PS512，ES256，ES384，ES512;
         *          PS256，PS384, PS512需要JDK 11或兼容JCA提供商（像BouncyCastle的）在运行路径中;
         *      b. 通过getPrivate() 获取私钥用于jwt加密,gerPublic() 获取公钥用户jwt解密(非对称加密);
         *
         */
        // 方法1:
        // Key key1 = Keys.hmacShaKeyFor("不同的加密算法有不同的字节长度要求".getBytes());
        // Key key2 = Keys.hmacShaKeyFor("不同的加密算法有不同的字节长度要求".getBytes());
        // String jws = jwtEncrypt(key1);
        // jwtParser(key2, jws);

        // 方法2:
        // Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        // String jws = jwtEncrypt(key1);
        // jwtParser(key,jws);

        // 方法3:
        KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.RS256);
        Key keyPrivate = keyPair.getPrivate();
        Key keyPublic = keyPair.getPublic();
        String jwt = jwtEncrypt(keyPrivate);
        jwtParser(keyPublic, jwt);

    }

    public static String jwtEncrypt(Key key) {

        System.out.println("===========创建JWT=============");
        JwtBuilder builder = Jwts.builder()
                /**
                 * 设置头部信息
                 *  自动补充 "alg": "HS256",
                 */
                .setHeaderParam("typ", "JWT")
                /**
                 * 设置载荷信息:
                 * iss: jwt签发者
                 * sub: jwt所面向的用户
                 * aud: 接收jwt的一方
                 * exp: jwt的过期时间，这个过期时间必须要大于签发时间
                 * nbf: 定义在什么时间之前，该jwt都是不可用的.
                 * iat: jwt的签发时间
                 * jti: jwt的唯一身份标识，主要用来作为一次性token,从而回避重放攻击
                 */
                .setId(UUID.randomUUID().toString())
                .setSubject("admin")
                .setIssuedAt(new Date())
                /**
                 * 公共的声明可以添加任何的信息，
                 * 一般添加用户的相关信息或其他业务需要的必要信息，
                 * 但不建议添加敏感信息，因为该部分在客户端可解密。
                 */
                .claim("id", "123456")
                .claim("name", "tbb")
                .claim("sex", "man")
                /**
                 * 签证
                 */
                .signWith(key);

        // 编码
        String jwt = builder.compact();
        System.out.println("生成的jwt: " + jwt);

        return jwt;
    }

    public static Jws<Claims> jwtParser(Key key, String jwt) {


        System.out.println("============解析jwt==============");

        try {
            Jws<Claims> result = Jwts.parser().setSigningKey(key).parseClaimsJws(jwt);
            // 以下步骤随实际情况而定,只要上一行代码执行不抛异常就证明jwt是有效的,合法的
            Claims body = result.getBody();

            System.out.println("载荷-标准中注册的声明id: " + body.getId());
            System.out.println("载荷-标准中注册的声明subject: " + body.getSubject());
            System.out.println("载荷-标准中注册的声明issueAt: " + body.getIssuedAt());
            System.out.println("=================================");
            System.out.println("载荷-公共的声明id: " + body.get("id"));
            System.out.println("载荷-公共的声明name: " + body.get("name"));
            System.out.println("载荷-公共的声明sex: " + body.get("sex"));

            return result;
        } catch (JwtException e) {
            // jwt不合法或者过期都会抛异常
            e.printStackTrace();
            return null;
        }

    }

    /**
     * 数据库查询key
     */
    public static Jws<Claims> jwtParser(String jwt) {

        System.out.println("============解析jwt==============");

        try {
            Jws<Claims> result = Jwts.parser().setSigningKeyResolver(new SigningKeyResolver() {
                @Override
                public Key resolveSigningKey(JwsHeader jwsHeader, Claims claims) {
                    String id = claims.getId();
                    // 通过id后台查询数据库返回key
                    return null;
                }

                @Override
                public Key resolveSigningKey(JwsHeader jwsHeader, String s) {
                    return null;
                }
            }).parseClaimsJws(jwt);
            // 以下步骤随实际情况而定,只要上一行代码执行不抛异常就证明jwt是有效的,合法的
            Claims body = result.getBody();

            System.out.println("载荷-标准中注册的声明id: " + body.getId());
            System.out.println("载荷-标准中注册的声明subject: " + body.getSubject());
            System.out.println("载荷-标准中注册的声明issueAt: " + body.getIssuedAt());
            System.out.println("=================================");
            System.out.println("载荷-公共的声明id: " + body.get("id"));
            System.out.println("载荷-公共的声明name: " + body.get("name"));
            System.out.println("载荷-公共的声明sex: " + body.get("sex"));

            return result;
        } catch (JwtException e) {
            // jwt不合法或者过期都会抛异常
            e.printStackTrace();
            return null;
        }

    }
}