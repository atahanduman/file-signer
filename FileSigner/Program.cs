using System;
using System.IO;
using System.Security.Cryptography;
using Newtonsoft.Json;
namespace FileSigner
{
    class Program
    {
        public static RSAParameters rsaParameters { get; private set; }
        static void Main(string[] args)
        {
            try
            {
                using (RSA rsa = RSA.Create(2048))
                {
                    rsaParameters = rsa.ExportParameters(true);
                }

                //Program.StoreParameters("C:\\Users\\ataha\\source\\repos\\FileSigner\\param.txt", rsaParameters);
                rsaParameters = Program.GetParameters("C:\\Users\\ataha\\source\\repos\\FileSigner\\param.txt");
                //Console.WriteLine(rsaParameters);
                byte[] file = Program.GetFile("C:\\Users\\ataha\\source\\repos\\FileSigner\\testLog.log");

                //byte[] signedHash = Program.SignFile(file, rsaParameters);
                byte[] signedHash; //= Program.SignFile(file, rsaParameters);

                using (StreamReader sw = new StreamReader("C:\\Users\\ataha\\source\\repos\\FileSigner\\signed.txt"))
                {
                    signedHash = JsonConvert.DeserializeObject<byte[]>(sw.ReadToEnd());
                    sw.Close();
                }


                if (Program.CheckSignature(signedHash, file, rsaParameters))
                {
                    Console.WriteLine("The signature was verified.");
                }
                else
                {
                    Console.WriteLine("The signature was not verified.");
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }

        static byte[] SignFile(byte[] file, RSAParameters rsaParameters)
        {
            try
            {
                //Create a new instance of RSA.
                using (RSA rsa = RSA.Create(rsaParameters))
                {
                    //The hash to sign.
                    byte[] hash;
                    using (SHA256 sha256 = SHA256.Create())
                    {
                        hash = sha256.ComputeHash(file);
                    }

                    //Create an RSASignatureFormatter object and pass it the 
                    //RSA instance to transfer the key information.
                    RSAPKCS1SignatureFormatter RSAFormatter = new RSAPKCS1SignatureFormatter(rsa);

                    //Set the hash algorithm to SHA256.
                    RSAFormatter.SetHashAlgorithm("SHA256");
                    //Create a signature for HashValue and return it.
                    byte[] SignedHash = RSAFormatter.CreateSignature(hash);

                    using (StreamWriter sw = new StreamWriter("C:\\Users\\ataha\\source\\repos\\FileSigner\\signed.txt"))
                    {
                        sw.WriteLine(JsonConvert.SerializeObject(SignedHash));
                        sw.Close();
                    }

                    return SignedHash;
                }
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);
                return null;
            }
        }

        static bool CheckSignature(byte[] signedHash, byte[] file, RSAParameters rsaParameters)
        {
            try
            {
                //Create a new instance of RSA.
                using (RSA rsa = RSA.Create(rsaParameters))
                {
                    //The hash to sign.
                    byte[] hash;
                    using (SHA256 sha256 = SHA256.Create())
                    {
                        hash = sha256.ComputeHash(file);
                    }

                    //Create an RSAPKCS1SignatureDeformatter object and pass it the  
                    //RSA instance to transfer the key information.
                    RSAPKCS1SignatureDeformatter RSADeformatter = new RSAPKCS1SignatureDeformatter(rsa);
                    RSADeformatter.SetHashAlgorithm("SHA256");
                    //Verify the hash and display the results to the console. 
                    if (RSADeformatter.VerifySignature(hash, signedHash))
                    {
                        return true;
                    }
                    else
                    {
                        return false;
                    }
                }
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);
                return false;
            }
        }

        static byte[] GetFile(string filename)
        {
            try
            {
                using (FileStream fs = new FileStream(filename, FileMode.Open, FileAccess.Read))
                {
                    // Create a byte array of file stream length
                    byte[] bytes = System.IO.File.ReadAllBytes(filename);
                    //Read block of bytes from stream into the byte array
                    fs.Read(bytes, 0, System.Convert.ToInt32(fs.Length));
                    //Close the File Stream
                    fs.Close();
                    return bytes; //return the byte data
                }
            }
            catch (IOException e)
            {
                Console.WriteLine(e.Message);
                return null;
            }
        }

        static void StoreParameters(string filename, RSAParameters rsaParameters)
        {
            try
            {
                string serializeParameters = JsonConvert.SerializeObject(rsaParameters);

                using (StreamWriter sw = new StreamWriter(filename))
                {
                    sw.WriteLine(serializeParameters);

                    //Close the File Stream
                    sw.Close();
                }
            }
            catch (IOException e)
            {
                Console.WriteLine(e.Message);
            }
        }

        static RSAParameters GetParameters(string filename)
        {
            try
            {
                RSAParameters rsaParameters;

                using (StreamReader sr = new StreamReader(filename))
                {
                    var data = sr.ReadToEnd();
                    rsaParameters = JsonConvert.DeserializeObject<RSAParameters>(data);
                    //Close the File Stream
                    sr.Close();
                    return rsaParameters;
                }
            }
            catch (IOException e)
            {
                Console.WriteLine(e.Message);
                return rsaParameters;
            }
        }
    }
}
