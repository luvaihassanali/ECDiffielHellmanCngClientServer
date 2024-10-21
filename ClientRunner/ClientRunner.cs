using System;
using System.Diagnostics;

namespace ClientRunner
{
    internal class ClientRunner
    {
        static void Main(string[] args)
        {
            string clientExePath = @"..\..\..\Client\bin\Debug\Client.exe";
            int numberOfInstances = 5;

            for (int i = 0; i < numberOfInstances; i++)
            {
                Process process = new Process();
                process.StartInfo.FileName = clientExePath;
                process.Start();
            }

            Console.WriteLine($"{numberOfInstances} test clients have been started.");
        }
    }
}
