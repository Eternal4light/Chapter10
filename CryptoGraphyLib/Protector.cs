using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using System.Security.Principal; //АИА

namespace CryptoGraphyLib
{
    public static class Protector
    {
        //размер соли должен составлять не менее 8 байт
        //пусть будет 16 байт

        private static readonly byte[] salt = Encoding.Unicode.GetBytes("7BANANAS");

        //число итераций должно быть не менее 1000
        //пусть будет 2000

        private static readonly int iterations = 2000;






        public static string Encrypt(string plainText, string password)
        {
            byte[] plainBytes = Encoding.Unicode.GetBytes(plainText);
            var aes = Aes.Create();
            var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations);
            aes.Key = pbkdf2.GetBytes(32);  //установить 256-битный ключ
            aes.IV = pbkdf2.GetBytes(16); //и 128-битный вектор инициализации

            var ms = new MemoryStream();
            using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
            {
                cs.Write(plainBytes, 0, plainBytes.Length);
            }
            return Convert.ToBase64String(ms.ToArray());
        }






        public static string Decrypt(string cryptoText, string password)
        {
            byte[] cryptoBytes = Convert.FromBase64String(cryptoText);
            var aes = Aes.Create();
            var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations);
            aes.Key = pbkdf2.GetBytes(32);
            aes.IV = pbkdf2.GetBytes(16);
            var ms = new MemoryStream();
            using (var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
            {
                cs.Write(cryptoBytes, 0, cryptoBytes.Length);
            }
            return Encoding.Unicode.GetString(ms.ToArray());
        }





        private static Dictionary<string, User> Users = new Dictionary<string, User>();

        public static User Register(string username, string password, string[] roles = null)  //добавлены роли для авторизации и аутентификации
        {
            //генерация соли
            var rng = RandomNumberGenerator.Create();
            var saltBytes = new byte[16];
            rng.GetBytes(saltBytes);
            var saltText = Convert.ToBase64String(saltBytes);

            //генерация соленго и хешированнго пароля
            var sha = SHA256.Create();
            var saltedPassword = password + saltText;
            var saltedhashedPassword = Convert.ToBase64String(sha.ComputeHash(Encoding.Unicode.GetBytes(saltedPassword)));

            var user = new User
            {
                Name = username,
                Salt = saltText,
                SaltedHashedPassword = saltedhashedPassword,
                Roles = roles               //АИА


            };
            Users.Add(user.Name, user);
            return user;

        }



        public static bool CheckPassword(string username, string password)
        {
            if (!Users.ContainsKey(username))
            {
                return false;
            }
            var user = Users[username];

            //повторная генерация соленого и хешированного пароля
            var sha = SHA256.Create();
            var saltedPassword = password + user.Salt;
            var saltedhashedPassword = Convert.ToBase64String(sha.ComputeHash(Encoding.Unicode.GetBytes(saltedPassword)));

            return (saltedhashedPassword == user.SaltedHashedPassword);
        }









        //работа с подписями


        public static string PublicKey;
        public static string ToXmlStringExt(this RSA rsa, bool includePrivateParameters)
        {
            var p = rsa.ExportParameters(includePrivateParameters);
            XElement xml;
            if (includePrivateParameters)
            {
                xml = new XElement("RSAKeyValue", 
                    new XElement("Modulus", Convert.ToBase64String(p.Modulus)),
                    new XElement("Exponent", Convert.ToBase64String(p.Exponent)),
                    new XElement("P", Convert.ToBase64String(p.P)),
                    new XElement("Q", Convert.ToBase64String(p.Q)),
                    new XElement("DP", Convert.ToBase64String(p.DP)),
                    new XElement("InverseQ", Convert.ToBase64String(p.InverseQ)));

            }
            else
            {

                xml = new XElement("RSAKeyValue",
                    new XElement("Modulus", Convert.ToBase64String(p.Modulus)),
                    new XElement("Exponent", Convert.ToBase64String(p.Exponent)));
            }
            return xml?.ToString();
        }


        public static void FromXmlStringExt (this RSA rsa, string parametersAsXml)
        {
            var xml = XDocument.Parse(parametersAsXml);
            var root = xml.Element("RSAKeyValue");
            var p = new RSAParameters
            {
                Modulus = Convert.FromBase64String(root.Element("Modulus").Value),
                Exponent = Convert.FromBase64String(root.Element("Exponent").Value)
            };
            if (root.Element("P") !=null)
            {
                p.P = Convert.FromBase64String(root.Element("P").Value);
                p.Q = Convert.FromBase64String(root.Element("Q").Value);
                p.DP = Convert.FromBase64String(root.Element("DP").Value);
                p.DQ = Convert.FromBase64String(root.Element("DQ").Value);
                p.InverseQ = Convert.FromBase64String(root.Element("InverseQ").Value);
            }
            rsa.ImportParameters(p);
        }


        public static string GenerateSignature(string data)
        {
            byte[] dataBytes = Encoding.Unicode.GetBytes(data);
            var sha = SHA256.Create();
            var hashedData = sha.ComputeHash(dataBytes);

            var rsa = RSA.Create();
            PublicKey = rsa.ToXmlStringExt(false);  //исключение закрытого ключа

            return Convert.ToBase64String(rsa.SignHash(hashedData, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        }

        public static bool ValidateSignature(string data, string signature)
        {
            byte[] dataBytes = Encoding.Unicode.GetBytes(data);
            var sha = SHA256.Create();
            var hashedData = sha.ComputeHash(dataBytes);

            byte[] signatureBytes = Convert.FromBase64String(signature);

            var rsa = RSA.Create();
            rsa.FromXmlStringExt(PublicKey);

            return rsa.VerifyHash(hashedData, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        }



        //Генерация случайных чисел
        public static byte[] GetRandomKeyOrIV(int size)
        {
            var r = RandomNumberGenerator.Create();
            var data = new byte[size];
            r.GetNonZeroBytes(data);                   //криптографически наполняемый массив
                                                       //сильные случайные байты
            return data;                                        
        }





        //АИА
        public static void RegisterSomeUsers()
        {
            Register("Alice", "Pa$$w0rd", new[] { "Admins" });
            Register("Bob", "Pa$$w0rd", new[] { "Sales", "TeamLeads" });
            Register("Eve", "Pa$$w0rd");
        }


        public static void LogIn( string username, string password)
        {
            if (CheckPassword(username, password))
            {
                var identity = new GenericIdentity(username, "PacktAuth");
                var principal = new GenericPrincipal(identity, Users[username].Roles);
                System.Threading.Thread.CurrentPrincipal = principal;
            }
        }
        





    }
}
