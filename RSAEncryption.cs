using System;
using System.Collections.Generic;
using System.Text;

using Org.BouncyCastle.Security;

namespace ISES.ClientForms.Crypto.DebuggerEngine
{
    public class RSA : System.MarshalByRefObject  
    {
        /// <summary>
        /// 生成Key
        /// </summary>
        /// <param name="Strength">密钥强度(512、768、1024、2048)</param>
        /// <param name="Certainty">允许的素数不确定性的度量</param>
        public void GenerateKeyPair(int Strength,
                                        int Certainty,
                                        ref string p1,
                                        ref string q1,
                                        ref string n1,
                                        ref string d1,
                                        ref string e1,
                                        ref string dP1,
                                        ref string dQ1,
                                        ref string qInv1)
        {
            BigInteger p = new BigInteger(p1);
            BigInteger q = new BigInteger(q1);
            BigInteger n = new BigInteger(n1);
            BigInteger d = new BigInteger(d1);
            BigInteger e = new BigInteger(e1);
            BigInteger dP = new BigInteger(dP1);
            BigInteger dQ = new BigInteger(dQ1);
            BigInteger qInv = new BigInteger(qInv1);

            /* 启动代码跟踪， F10：逐方法跟踪，F11：逐语句跟踪，F5：直接执行不跟踪，Shift+F11：跳出方法。 */
            System.Diagnostics.Debugger.Launch();

            SecureRandom Random = new SecureRandom();  /* 声明强加密随机数生成器，用于生成随机大素数 */

            /* 取得p和q的位长，是密钥强度的一半。 */
            int strength = Strength;
            int pbitlength = (strength + 1) / 2;
            int qbitlength = (strength - pbitlength);
            int mindiffbits = strength / 3;

            /* 公钥指数e */
            e = new BigInteger("65537");

            // TODO Consider generating safe primes for p, q (see DHParametersHelper.generateSafePrimes)
            // (then p-1 and q-1 will not consist of only small factors - see "Pollard's algorithm")

            /* 生成p  */
            for (; ; )
            {
                p = new BigInteger(pbitlength, 1, Random);  /* 构造一个随机生成的具有指定 bitLength 的可能是素数的大整数。 */


                if (p.Mod(e).Equals(BigInteger.One))   /* 判断p与e的模不是1 */
                    continue;

                if (!p.IsProbablePrime(Certainty))     /* 以允许的不确定性的度量Certainty判断p是否是素数  */
                    continue;

                if (e.Gcd(p.Subtract(BigInteger.One)).Equals(BigInteger.One))   /* 判断e与p-1的最大公约数是1 */
                    break;
            }

            /* 生成n */
            for (; ; )
            {
                /*  生成q  */
                for (; ; )
                {
                    q = new BigInteger(qbitlength, 1, Random); /* 构造一个随机生成的具有指定 bitLength 的可能是素数的大整数。 */

                    if (q.Subtract(p).Abs().BitLength < mindiffbits)
                        continue;

                    if (q.Mod(e).Equals(BigInteger.One))  /* 判断q与e的模不是1 */
                        continue;

                    if (!q.IsProbablePrime(Certainty))   /* 以允许的不确定性的度量Certainty判断p是否是素数  */
                        continue;

                    if (e.Gcd(q.Subtract(BigInteger.One)).Equals(BigInteger.One))  /* 判断e与q-1的最大公约数是1 */
                        break;
                }

                /* 计算n */
                n = p.Multiply(q);

                if (n.BitLength == Strength)  /* 判断n的位长是否等于密钥强度 */
                    break;

                /* 如果得到的素数不够大，将p赋值为较大的素数再试 */
                p = p.Max(q);
            }


            /* 临时变量 */
            BigInteger pSub1, qSub1, phi;

            if (p.CompareTo(q) < 0)  /* 如果p小于q则交换p和q */
            {
                phi = p;
                p = q;
                q = phi;
            }

            pSub1 = p.Subtract(BigInteger.One);
            qSub1 = q.Subtract(BigInteger.One);
            phi = pSub1.Multiply(qSub1);    /*   phi=(p-1)*(q-1)   */

            /* 私钥指数d */
            d = e.ModInverse(phi);

            /* 计算dP、dQ、qInv */
            dP = d.Remainder(pSub1);
            dQ = d.Remainder(qSub1);
            qInv = q.ModInverse(p);


            p1 = p.ToString();
            q1 = q.ToString();
            n1 = n.ToString();
            d1 = d.ToString();
            e1 = e.ToString();
            dP1 = dP.ToString();
            dQ1 = dQ.ToString();
            qInv1 = qInv.ToString();
        }


        /// <summary>
        /// 执行加密运算
        /// </summary>
        /// <param name="InputByte">输入的字节数组</param>
        /// <param name="Strength">密钥强度(512、768、1024、2048)</param>
        /// <param name="Exponent">公钥指数或私钥指数</param>
        /// <param name="Modulus">模数</param>
        public string Cipher(byte[] InputByte, int Strength, string E, string M) 
        {
            BigInteger Exponent = new BigInteger(E);
            BigInteger Modulus = new BigInteger(M);

            /* 启动代码跟踪， F10：逐方法跟踪，F11：逐语句跟踪，F5：直接执行不跟踪，Shift+F11：跳出方法。 */
            System.Diagnostics.Debugger.Launch();

            /* 计算可加密的最大明文字节长度 */
            int maxLength = (Strength + 7) / 8;

            if (InputByte.Length > maxLength)
                throw new Exception("输入过大。");

            /* 转换字节数组为大整数 */
            BigInteger input = new BigInteger(1, InputByte, 0, InputByte.Length);

            if (input.CompareTo(Modulus) >= 0)
                throw new Exception("输入过大");

            /* 加密运算 */
            BigInteger output =  input.ModPow(Exponent, Modulus);

            return output.ToString();
        }
    }
}
