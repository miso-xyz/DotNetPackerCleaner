using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Reflection;

namespace DotNetPackerDeobfuscator
{
    class Program
    {
        static void PrintRenamed(string from, string to, string type)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("[Renamed]: ");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write("'" + from + "' -> '" + to + "'");
            if (type == "")
            {
                Console.WriteLine();
                return;
            }
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.Write(" (" + type + ")");
            Console.WriteLine();
        }

        static void PrintRemoved(string name, string type)
        {
            Console.ForegroundColor = ConsoleColor.DarkRed;
            Console.Write("[Removed]: ");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("'" + name + "'");
            if (type == "")
            {
                Console.WriteLine();
                return;
            }
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write(" (" + type + ")");
            Console.WriteLine();
        }

        static void PrintStringFixed(string from, string to, string path)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("[String Fixed]: ");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("'" + from + "' -> '" + to + "'");
            if (path == "")
            {
                Console.WriteLine();
                return;
            }
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write(" (" + path + ")");
            Console.WriteLine();
        }

        public static ModuleDefMD asm;
        //public static Assembly app;

        static void Main(string[] args)
        {
            Console.Title = "DotNetPacker Cleaner";
            Console.WriteLine("DotNetPacker Cleaner by misonothx");
            Console.WriteLine(" |- https://github.com/miso-xyz/DotNetPackerCleaner");
            Console.WriteLine();
            asm = ModuleDefMD.Load(args[0]);
            asm.EntryPoint.DeclaringType.Name = "MainClass";
            asm.EntryPoint.Name = "Main";
            var removeTypes = new List<string>() { "AssemblyInfoAttribute", "ConfusedByAttribute", "DotfuscatorAttribute", "DotNetPatcherObfuscatorAttribute", "dotNetProtector", "ObfuscatedByGoliath", "PoweredByAttribute" };
            int renamedCounter = 0, removedCounter = 0, stringFixedCounter = 0;
            bool fixedUtf32 = false, fixedDecryptStrings = false, fixedDecryptedBytes = false, fixedBoolUtils = false, hasCompressedResources = false;
            //bool utilsRenamed = false;
            for (int x = 0; x < asm.Assembly.CustomAttributes.Count; x++)
            {
                if (removeTypes.Contains(asm.Assembly.CustomAttributes[x].TypeFullName)) { PrintRemoved(asm.Assembly.CustomAttributes[x].TypeFullName, "Custom Attribute (Assembly)"); asm.Assembly.CustomAttributes.RemoveAt(x); x = 0; removedCounter++; }
            }
            for (int x = 0; x < asm.CustomAttributes.Count; x++)
            {
                PrintRemoved(asm.CustomAttributes[x].AttributeType.ToString(), "Custom Attribute (Module)");
                removedCounter++;
            }
            asm.CustomAttributes.Clear();
            for (int x = 0; x < asm.Types.Count; x++)
            {
                if (removeTypes.Contains(asm.Types[x].Name)) { PrintRemoved(asm.Types[x].Name, "class"); asm.Types.RemoveAt(x); x = 0; removedCounter++; }
            }
            foreach (var t_ in asm.Types)
            {
                int stringMethodCount = 0;
                if (t_.HasCustomAttributes)
                {
                    foreach (var cAtr in t_.CustomAttributes)
                    {
                        if (cAtr.HasConstructorArguments)
                        {
                            foreach (var cAtrCA in cAtr.ConstructorArguments)
                            {
                                string oldTypeName = t_.Name;
                                if (t_.BaseType.FullName.Contains("Console"))
                                {
                                    t_.Name = "MyApplication";
                                    t_.Namespace = Path.GetFileNameWithoutExtension(asm.Name) + ".My";
                                    PrintRenamed(oldTypeName, "MyApplication", "class");
                                    renamedCounter++;
                                    continue;
                                }
                                if (cAtrCA.Value.ToString().Contains("Resources"))
                                {
                                    t_.Name = "Resources";
                                    t_.Namespace = Path.GetFileNameWithoutExtension(asm.Name) + ".My.Resources";
                                    PrintRenamed(oldTypeName, "Resources", "class");
                                    renamedCounter++;
                                    continue;
                                }
                                if (cAtrCA.Value.ToString().Contains("MyTemplate") && !t_.IsSealed)
                                {
                                    t_.Name = "MyComputer";
                                    t_.Namespace = Path.GetFileNameWithoutExtension(asm.Name) + ".My";
                                    PrintRenamed(oldTypeName, "MyComputer", "class");
                                    renamedCounter++;
                                    continue;
                                }
                                if (cAtrCA.Value.ToString().Contains("MyTemplate") && t_.IsSealed)
                                {
                                    t_.Name = "MyProject";
                                    t_.Namespace = Path.GetFileNameWithoutExtension(asm.Name) + ".My";
                                    PrintRenamed(oldTypeName, "MyProject", "class");
                                    renamedCounter++;
                                    continue;
                                }
                                if (cAtrCA.Value.ToString().Contains("SettingsDesigner"))
                                {
                                    t_.Name = "MySettings";
                                    t_.Namespace = Path.GetFileNameWithoutExtension(asm.Name) + ".My";
                                    PrintRenamed(oldTypeName, "MySettings", "class");
                                    renamedCounter++;
                                    continue;
                                }
                            }
                        }
                    }
                }
                foreach (var methods in t_.Methods)
                {
                    if (methods.HasImplMap)
                    {
                        if (methods.ImplMap.Name == "VirtualProtect")
                        {
                            PrintRenamed(t_.Name, "AntiDump", "class");
                            PrintRenamed(methods.Name, "kernel32_VirtualProtect", "method");
                            methods.Name = "kernel32_VirtualProtect";
                            t_.Name = "AntiDump";
                            t_.Namespace = "DotNetPacker.Protections";
                            renamedCounter += 2;
                            continue;
                        }
                    }
                    if (!methods.HasBody) { continue; }
                    if (methods.Body.Instructions.Count > 17)
                    {
                        if (methods.Body.HasVariables && methods.Body.Instructions[0].OpCode.Equals(OpCodes.Ldstr) && methods.Body.Instructions[3].IsLdcI4())
                        {
                            methods.Name = "MethodString_" + stringMethodCount++;
                            string stringToDecrypt = methods.Body.Instructions[0].Operand.ToString();
                            int intKey = methods.Body.Instructions[3].GetLdcI4Value();
                            if (!fixedDecryptedBytes && !fixedDecryptStrings && !fixedUtf32)
                            {
                                foreach (var t__ in asm.Types)
                                {
                                    foreach (var methods_ in t__.Methods)
                                    {
                                        string oldMethodName = methods_.Name;
                                        string oldTypeName = t__.Name;
                                        if (methods.Body.Instructions[6].Operand.ToString().Contains(t__.Name))
                                        {
                                            methods_.Name = "FromUTF32";
                                            t__.Name = "UTF32Utils";
                                            PrintRenamed(oldMethodName, "FromUTF32", "method");
                                            PrintRenamed(oldTypeName, "UTF32Utils", "class");
                                            renamedCounter += 2;
                                            fixedUtf32 = true;
                                        }
                                        else if (methods.Body.Instructions[10].Operand.ToString().Contains(t__.Name))
                                        {
                                            methods_.Name = "DecryptString";
                                            t__.Name = "StringResolver";
                                            PrintRenamed(oldMethodName, "DecryptString", "method");
                                            PrintRenamed(oldTypeName, "StringResolver", "class");
                                            renamedCounter += 2;
                                            fixedDecryptStrings = true;
                                        }
                                        else if (methods.Body.Instructions[14].Operand.ToString().Contains(t__.Name))
                                        {
                                            methods_.Name = "GetStringFromDecryptedBytes";
                                            t__.Name = "StringResolver";
                                            PrintRenamed(oldMethodName, "GetStringFromDecryptedBytes", "method");
                                            PrintRenamed(oldTypeName, "StringResolver", "class");
                                            renamedCounter += 2;
                                            fixedDecryptedBytes = true;
                                        }
                                    }
                                }
                            }
                        }
                        if (methods.Body.Instructions[6].Operand != null && !fixedBoolUtils)
                        {
                            if (methods.Body.Instructions[6].Operand.ToString().Contains("Math::Round"))
                            {
                                PrintRenamed(t_.Name, "BoolUtils", "class");
                                PrintRenamed(methods.Name, "GetBoolFromInt", "method");
                                t_.Name = "BoolUtils";
                                methods.Name = "GetBoolFromInt";
                                t_.Namespace = "DotNetPacker.Protections";
                                renamedCounter += 2;
                                continue;
                            }
                        }
                        if (methods.Body.Instructions.Count > 65)
                        {
                            if (methods.Body.Instructions[65].OpCode.Equals(OpCodes.Newobj))
                            {
                                if (methods.Body.Instructions[65].Operand.ToString().Contains("BadImageFormatException"))
                                {
                                    PrintRenamed(t_.Name, "AntiTamper", "class");
                                    PrintRenamed(t_.Name, "CompareMD5Hash", "method");
                                    methods.Name = "CompareMD5Hash";
                                    t_.Name = "AntiTamper";
                                    t_.Namespace = "DotNetPacker.Protections";
                                    foreach (var methods_ in t_.Methods)
                                    {
                                        if (methods_.Name != methods.Name && methods.HasBody)
                                        {
                                            methods_.Name = "MethodString_" + stringMethodCount++;
                                        }
                                    }
                                    foreach (Instruction inst in methods.Body.Instructions)
                                    {
                                        int baseInst = methods.Body.Instructions.IndexOf(inst);
                                        if (inst.OpCode.Equals(OpCodes.Call))
                                        {
                                            if (inst.Operand.ToString().Contains("MethodString"))
                                            {
                                                fixMethodString(t_.Name, inst.Operand.ToString().Split(':')[2].Replace("(System.Boolean)", null), methods.Body.Instructions[baseInst - 2].GetLdcI4Value());
                                                stringFixedCounter++;
                                            }
                                        }
                                    }
                                    methods.Body.Instructions.Clear();
                                    methods.Body.Instructions.Add(OpCodes.Ldstr.ToInstruction("AntiTampering Algorithm go brrrrrrrr"));
                                    methods.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                                    stringFixedCounter++;
                                    renamedCounter += 2;
                                    continue;
                                }
                            }
                        }
                        else if (methods.Body.Instructions[7].OpCode.Equals(OpCodes.Call) && methods.Body.Instructions[5].OpCode.Equals(OpCodes.Call))
                        {
                            if (methods.Body.Instructions[7].Operand.ToString().Contains("IsLogging") && methods.Body.Instructions[5].Operand.ToString().Contains("IsAttached"))
                            {
                                PrintRenamed(t_.Name, "AntiDebug", "class");
                                PrintRenamed(methods.Name, "CheckForDebugger", "method");
                                methods.Name = "CheckForDebugger";
                                t_.Name = "AntiDebug";
                                t_.Namespace = "DotNetPacker.Protections";
                                renamedCounter += 2;
                                continue;
                            }
                        }
                        else if (methods.Body.Instructions[4].OpCode.Equals(OpCodes.Newobj) && methods.Body.Instructions[8].OpCode.Equals(OpCodes.Call))
                        {
                            if (methods.Body.Instructions[4].Operand.ToString().Contains("GZipStream") && methods.Body.Instructions[8].Operand.ToString().Contains(t_.Name))
                            {
                                PrintRenamed(methods.Name, "Decompress", "method");
                                PrintRenamed(t_.Name, "Resources", "class");
                                methods.Name = "Decompress";
                                t_.Name = "Resources";
                                t_.Namespace = "DotNetPacker.Protections";
                                renamedCounter += 2;
                                hasCompressedResources = true;
                                continue;
                            }
                        }
                    }
                }
            }
            foreach (var t_ in asm.Types)
            {
                foreach (var methods in t_.Methods)
                {
                    if (t_.Name == "<Module>")
                    {
                        for (int x = 0; x < methods.Body.Instructions.Count; x++)
                        {
                            Instruction inst = methods.Body.Instructions[x];
                            if (hasCompressedResources)
                            {
                                for (int x_ = 0; x_ < methods.Body.Instructions.Count; x_++)
                                {
                                    Instruction temp_;
                                    if (!methods.Body.Instructions[x_].OpCode.Equals(OpCodes.Ret))
                                    {
                                        if (methods.Body.Instructions[x_].Operand.ToString().Contains("Resources"))
                                        {
                                            temp_ = methods.Body.Instructions[x_];
                                            methods.Body.Instructions.Clear();
                                            methods.Body.Instructions.Add(temp_);
                                            methods.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
                                            renamedCounter += methods.Body.Instructions.Count - 2; // ret & compression are kept
                                        }
                                    }
                                }
                            }
                            else
                            {
                                methods.Body.Instructions.Clear();
                                renamedCounter += methods.Body.Instructions.Count;
                            }
                            PrintRemoved("Removed Protections", "call");
                            break;
                        }
                    }
                    if (!methods.HasBody) { continue; }
                    methods.Body.KeepOldMaxStack = true;
                    for (int x = 0; x < methods.Body.Instructions.Count; x++ )
                    {
                        Instruction inst = methods.Body.Instructions[x];
                        int baseInst = methods.Body.Instructions.IndexOf(inst);
                        if (inst.OpCode.Equals(OpCodes.Call))
                        {
                            if (inst.Operand.ToString().Contains("MethodString"))
                            {
                                fixMethodString(t_.Name, inst.Operand.ToString().Split(':')[2].Replace("(System.Boolean)", null), methods.Body.Instructions[baseInst - 2].GetLdcI4Value());
                                stringFixedCounter++;
                            }
                        }
                    }
                }
            }
            Console.ForegroundColor = ConsoleColor.DarkCyan;
            Console.WriteLine("###################################################");
            Console.ForegroundColor = ConsoleColor.DarkMagenta;
            Console.WriteLine("     " + renamedCounter + " Elements Renamed");
            Console.ForegroundColor = ConsoleColor.DarkRed;
            Console.WriteLine("     " + removedCounter + " Elements Removed (including protection calls)");
            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine("     " + stringFixedCounter + " Strings Fixed");
            Console.ForegroundColor = ConsoleColor.DarkCyan;
            Console.WriteLine("###################################################");
            ModuleWriterOptions moduleWriterOptions = new ModuleWriterOptions(asm);
            moduleWriterOptions.MetadataOptions.Flags |= MetadataFlags.PreserveAll;
            moduleWriterOptions.Logger = DummyLogger.NoThrowInstance;
            NativeModuleWriterOptions nativeModuleWriterOptions = new NativeModuleWriterOptions(asm, true);
            nativeModuleWriterOptions.MetadataOptions.Flags |= MetadataFlags.PreserveAll;
            nativeModuleWriterOptions.Logger = DummyLogger.NoThrowInstance;
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("Now saving '" + Path.GetFileNameWithoutExtension(args[0]) + "-DotNetUnpacked" + Path.GetExtension(args[0]) + "'...");
            try
            {
                asm.Write(Path.GetFileNameWithoutExtension(args[0]) + "-DotNetUnpacked" + Path.GetExtension(args[0]));
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("Successfully saved '" + Path.GetFileNameWithoutExtension(args[0]) + "-DotNetUnpacked" + Path.GetExtension(args[0]) + "'!");
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Failed to save '" + Path.GetFileNameWithoutExtension(args[0]) + "-DotNetUnpacked" + Path.GetExtension(args[0]) + "'! (" + ex.Message + ")");
            }
            Console.ResetColor();
            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }

        public static string returnWithEncoding(byte[] data, bool useDefaultTextEncoding)
        {
            if (useDefaultTextEncoding)
            {
                return Encoding.Default.GetString(data);
            }
            return Encoding.UTF8.GetString(data);
        }

        public static void fixMethodString(string typeName, string methodName, int boolVal)
        {
            MethodDef a_ = getMethod(typeName, methodName);
            bool b_ = GetBool(boolVal);
            string encString = a_.Body.Instructions[0].Operand.ToString();
            string decryptedString = returnWithEncoding(DecodeString(ToUTF32(a_.Body.Instructions[0].Operand.ToString(), a_.Body.Instructions[3].GetLdcI4Value()), b_), b_);
            a_.Body.Instructions.Clear();
            a_.Body.Instructions.Add(new Instruction(OpCodes.Ldstr, decryptedString));
            a_.Body.Instructions.Add(new Instruction(OpCodes.Ret));
            PrintStringFixed(encString, decryptedString, typeName + "::" + a_.Name);
        }

        public static MethodDef getMethod(string typeName, string methodName)
        {
            foreach (var t_ in asm.Types)
            {
                if (t_.Name == typeName)
                {
                    foreach (var methods in t_.Methods)
                    {
                        if (methods.Name == methodName)
                        {
                            return methods;
                        }
                    }
                }
            }
            return null;
        }

        public static bool GetBool(int integer)
        {
            bool result = true;
            checked
            {
                int num = Convert.ToInt32(Math.Round(Convert.ToDouble(integer) / 2.0));
                int num2 = 2;
                int num3 = num;
                for (int i = num2; i <= num3; i++)
                {
                    if (integer % i == 0)
                    {
                        result = false;
                    }
                }
                return result;
            }
        }

        public static string ToUTF32(string Kajm, int MvYz)
        {
            string text = string.Empty;
            checked
            {
                int num = Kajm.Length - 1;
                for (int i = 0; i <= num; i++)
                {
                    int utf = Convert.ToInt32(Kajm[i]) ^ MvYz;
                    text += char.ConvertFromUtf32(utf);
                }
                return text;
            }
        }

        public static byte[] DecodeString(string data, bool useDefaultTextEncoding)
        {
            checked
            {
                byte[] result;
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    byte[] bytes;
                    if (useDefaultTextEncoding)
                    {
                        bytes = Encoding.Default.GetBytes(data);
                    }
                    else
                    {
                        bytes = Encoding.UTF8.GetBytes(data);
                    }
                    using (FromBase64Transform fromBase64Transform = new FromBase64Transform())
                    {
                        byte[] array = new byte[fromBase64Transform.OutputBlockSize - 1 + 1];
                        int num = 0;
                        while (bytes.Length - num > 4)
                        {
                            fromBase64Transform.TransformBlock(bytes, num, 4, array, 0);
                            num += 4;
                            memoryStream.Write(array, 0, fromBase64Transform.OutputBlockSize);
                        }
                        array = fromBase64Transform.TransformFinalBlock(bytes, num, bytes.Length - num);
                        memoryStream.Write(array, 0, array.Length);
                        fromBase64Transform.Clear();
                    }
                    memoryStream.Position = 0L;
                    int num2;
                    if (memoryStream.Length > 0x7FFFFFFFL)
                    {
                        num2 = int.MaxValue;
                    }
                    else
                    {
                        num2 = Convert.ToInt32(memoryStream.Length);
                    }
                    byte[] array2 = new byte[num2 - 1 + 1];
                    memoryStream.Read(array2, 0, num2);
                    memoryStream.Close();
                    result = array2;
                }
                return result;
            }
        }
    }
}
