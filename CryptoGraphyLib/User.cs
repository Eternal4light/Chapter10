using System;
using System.Collections.Generic;
using System.Text;

namespace CryptoGraphyLib
{
    public class User
    {
        public string Name { get; set; }
        public string Salt { get; set; }
        public string SaltedHashedPassword { get; set; }

        //реализация аутентификации и авторизации
        public string[] Roles { get; set; }
    }
}
