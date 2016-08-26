using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Management.Automation;
using System.Security.Cryptography;
using System.IO;

namespace PSHashing
{
        
    /// <summary>
    /// Calculates Hashes for specified input.
    /// </summary>
    [Cmdlet(VerbsDiagnostic.Measure, "Hash", DefaultParameterSetName = "FileInput")]
    public class Hash : Cmdlet
    {

        [Parameter(Position = 0,ParameterSetName = "FileInput", Mandatory = true, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
        [ValidateNotNull]
        public System.IO.FileInfo Path { get; set; }

        [Parameter(Position = 0, ParameterSetName = "StringInput", Mandatory = true, ValueFromPipeline = true)]
        [ValidateNotNull]
        public string StringValue { get; set; }

        [Parameter(Position = 1)]
        [ValidateSet("md5", "sha1", "sha256", "sha384", "sha512", "ripemd160", IgnoreCase = true)]
        public string HashType { get; set; }

        [Parameter(HelpMessage ="Let the cmdlet output a byte[] instead of a string.")]
        public SwitchParameter RawBytes { get; set; }

        [Parameter(HelpMessage ="Set so the cmdlet interprets paths as strings instead using the file.")]
        public SwitchParameter NoFile { get; set; }

        private HashAlgorithm Algorithm { get; set; }
        protected override void BeginProcessing()
        {
            base.BeginProcessing();
            switch (HashType.ToLower())
            {
                case "md5":
                    Algorithm = MD5.Create();
                    break;
                case "sha1":
                    Algorithm = SHA1.Create();
                    break;
                case "sha256":
                    Algorithm = SHA256.Create();
                    break;
                case "sha384":
                    Algorithm = SHA384.Create();
                    break;
                default:
                case "sha512":
                    Algorithm = SHA512.Create();
                    break;
                case "ripemd160":
                    Algorithm = RIPEMD160.Create();
                    break;
            }
        }

        protected override void ProcessRecord()
        {
            Stream input = null;

            try
            {
                if (StringValue != null)
                {
                    if (File.Exists(StringValue) && ! NoFile.IsPresent)
                    {
                        input = File.OpenRead(StringValue);
                        WriteVerbose($"{StringValue} interpreted as File.");
                    }
                    else
                    {
                        input = new MemoryStream(Encoding.UTF8.GetBytes(StringValue));
                        WriteVerbose($"{StringValue} interpreted as String.");
                    }
                }
                else if (Path != null)
                {
                    input = Path.OpenRead();
                    WriteVerbose($"{Path} interpreted as String.");
                }
                else
                {
                    WriteWarning("Input not found");
                    return;
                }

                var output = Algorithm.ComputeHash(input);
                if (RawBytes.IsPresent)
                    WriteObject(output, false);
                else
                    WriteObject(BitConverter.ToString(output));
            }
            finally
            {
                input?.Dispose();
            }
        }

        protected override void EndProcessing()
        {
            base.EndProcessing();
            Algorithm.Dispose();
        }
    }
}
