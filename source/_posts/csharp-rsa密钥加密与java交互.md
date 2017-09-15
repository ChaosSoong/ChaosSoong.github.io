---
title: csharp rsa密钥加密与java交互
date: 2017-09-15 11:28:13
tags: [CSharp,rsa加密]
categories: CSharp
---
自从到了深圳以后一直在忙工作，都没有空闲时间来写点什么(其实还不是因懒)前两天接手了一个项目，一个身份验证，输入身份证和姓名来验证是否认证成功，(感觉对方公司挺厉害的，需要接入公安局的数据库)talk is cheap ,show your code

<!--more-->
## base64编码
    var data = new { terminal_id = terminal_id, trade_date = "20170913153750", trans_id = "14744392884941238", industry_type = "A1", id_holder = "your_name", is_photo = "photo", id_card ="your_id_card", member_id = member_id };
            var strJson = Newtonsoft.Json.JsonConvert.SerializeObject(data);
            //base64编码字符串
            string base64str = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(strJson)); 

其中用到了一个库，将对象序列化。
## rsa加密

根据密钥密码读取公钥和私钥信息：

    X509Certificate2 cert = new X509Certificate2(pfxPath, priKeyPass, X509KeyStorageFlags.Exportable |X509KeyStorageFlags.PersistKeySet);
                string prikey = cert.PrivateKey.ToXmlString(true);//公钥
                string pubkey = cert.PublicKey.Key.ToXmlString(false);//私钥
                return prikey.ToString();

使用的也是c#提供的类库
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

接下来是根据加密：

    RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                byte[] cipherbytes = new byte[] { };
                rsa.FromXmlString(privateKey);
                byte[] data = Encoding.UTF8.GetBytes(src.ToString());
                byte[] ss = new byte[1024];
                int length = 0;
                for (int i = 0; i < data.Length; i += 117)
                {
                    cipherbytes = rsa.Encrypt(data.Skip(i).Take(117).ToArray(), false);
                    length += cipherbytes.Length;
                    cipherbytes.CopyTo(ss, length);
                }
                byte[] result = ss.Skip(128).Take(length).ToArray();
                return result;

如果明文过长需要分组截取数据再进行加密(这是坑！！！)

然而把加密后的数据提交给对方后，返回数据解析失败，Google一系列之后，才有点眉目，他们那边是java生成的密钥，用私钥加密公钥解密。而c#正好相反，提供的类库是用公钥加密私钥解密，这就是问题所在。
当然有问题就要解决啦，有这样一个类库，大名鼎鼎的BouncyCastle，只是以前没有接触过
，私钥加密公钥解密，以下是方法：

    public class RSAForJava
    {
        public RSAForJava()
        {
        }
        /// <summary>
        /// KEY 结构体
        /// </summary>
        public struct RSAKEY
        {
            /// <summary>
            /// 公钥
            /// </summary>
            public string PublicKey
            {
                get;
                set;
            }
            /// <summary>
            /// 私钥
            /// </summary>
            public string PrivateKey
            {
                get;
                set;
            }
        }
        public RSAKEY GetKey()
        {
            //RSA密钥对的构造器  
            RsaKeyPairGenerator keyGenerator = new RsaKeyPairGenerator();
            //RSA密钥构造器的参数  
            RsaKeyGenerationParameters param = new RsaKeyGenerationParameters(
                BigInteger.ValueOf(3),
                new SecureRandom(),
                1024,   //密钥长度  
                25);
            //用参数初始化密钥构造器  
            keyGenerator.Init(param);
            //产生密钥对  
            AsymmetricCipherKeyPair keyPair = keyGenerator.GenerateKeyPair();
            //获取公钥和密钥  
            AsymmetricKeyParameter publicKey = keyPair.Public;
            AsymmetricKeyParameter privateKey = keyPair.Private;
            SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);
            PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);
            Asn1Object asn1ObjectPublic = subjectPublicKeyInfo.ToAsn1Object();
            byte[] publicInfoByte = asn1ObjectPublic.GetEncoded("UTF-8");
            Asn1Object asn1ObjectPrivate = privateKeyInfo.ToAsn1Object();
            byte[] privateInfoByte = asn1ObjectPrivate.GetEncoded("UTF-8");
            RSAKEY item = new RSAKEY()
            {
                PublicKey = Convert.ToBase64String(publicInfoByte),
                PrivateKey = Convert.ToBase64String(privateInfoByte)
            };
            return item;
        }
        private AsymmetricKeyParameter GetPublicKeyParameter(string s)
        {
            s = s.Replace("\r", "").Replace("\n", "").Replace(" ", "");
            byte[] publicInfoByte = Convert.FromBase64String(s);
            Asn1Object pubKeyObj = Asn1Object.FromByteArray(publicInfoByte);//这里也可以从流中读取，从本地导入   
            AsymmetricKeyParameter pubKey = PublicKeyFactory.CreateKey(publicInfoByte);
            return pubKey;
        }
        private AsymmetricKeyParameter GetPrivateKeyParameter(string s)
        {
            s = s.Replace("\r", "").Replace("\n", "").Replace(" ", "");
            byte[] privateInfoByte = Convert.FromBase64String(s);
            // Asn1Object priKeyObj = Asn1Object.FromByteArray(privateInfoByte);//这里也可以从流中读取，从本地导入   
            // PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);
            AsymmetricKeyParameter priKey = PrivateKeyFactory.CreateKey(privateInfoByte);
            return priKey;
        }
        public string EncryptByPrivateKey(string s, string key)
        {
            //非对称加密算法，加解密用  
            IAsymmetricBlockCipher engine = new Pkcs1Encoding(new RsaEngine());
            //加密  
            try
            {
                engine.Init(true, GetPrivateKeyParameter(key));
                byte[] byteData = System.Text.Encoding.UTF8.GetBytes(s);
                var ResultData = engine.ProcessBlock(byteData, 0, byteData.Length);
                return Convert.ToBase64String(ResultData);
                //Console.WriteLine("密文（base64编码）:" + Convert.ToBase64String(testData) + Environment.NewLine);
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }
        public string DecryptByPublicKey(string s, string key)
        {
            s = s.Replace("\r", "").Replace("\n", "").Replace(" ", "");
            //非对称加密算法，加解密用  
            IAsymmetricBlockCipher engine = new Pkcs1Encoding(new RsaEngine());
            //解密  
            try
            {
                engine.Init(false, GetPublicKeyParameter(key));
                byte[] byteData = Convert.FromBase64String(s);
                var ResultData = engine.ProcessBlock(byteData, 0, byteData.Length);
                return Encoding.UTF8.GetString(ResultData);
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }
    }

所以更改之后加密方法是这样的：

    //加载私钥  
            RSACryptoServiceProvider privateRsa = new RSACryptoServiceProvider();
            privateRsa.FromXmlString(xmlPrivateKey);
            //转换密钥  
            AsymmetricCipherKeyPair keyPair = DotNetUtilities.GetKeyPair(privateRsa);
            IBufferedCipher c = CipherUtilities.GetCipher("RSA/ECB/PKCS1Padding");
            c.Init(true, keyPair.Private);
            byte[] DataToEncrypt = Encoding.UTF8.GetBytes(strEncryptString);
            byte[] cipherbytes = new byte[] { };
            byte[] ss = new byte[1024];
            int length = 0;
            for (int i = 0; i < DataToEncrypt.Length; i += 117)
            {
                cipherbytes = c.DoFinal(DataToEncrypt.Skip(i).Take(117).ToArray());
                length += cipherbytes.Length;
                cipherbytes.CopyTo(ss, length);
            }
            byte[] result = ss.Skip(128).Take(length).ToArray();
            string str = byte2Hex(result);
            return str;

其中加密之后是字节数组result，需要把它转化成16进制字符串：

     private static string byte2Hex(byte[] bytes)
        {
            string returnStr = "";
            if (bytes != null)
            {
                for (int i = 0; i < bytes.Length; i++)
                {
                    returnStr += bytes[i].ToString("X2");
                }
            }
            return returnStr;
        }

## 总结
其实就是rsa加密算法java和c#交互问题，c#客户端和java服务器端。
1. 将数据进行base64编码
2. c#端根据java端传来的密钥及其密码提取私钥信息
3. c#端使用私钥进行加密，这里不能用自带的rsa类库加密算法，因为它只能用公钥加密私钥解密，需要使用第三方库BouncyCastle
4. 将加密结果转化为16进制字符串，post提交，ok

文章写得不好，看到的还请谅解，一起学习进步。