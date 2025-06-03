using System;
using System.IO;
using System.IO.Pipes;
using System.Text;

namespace VettaiyanNode.Common
{
    public class IPC
    {

        public static bool SendPathToScanner(string absolutePath)
        {
            try
            {
                using (var pipe = new NamedPipeClientStream(".", "VettaiyanScanner", PipeDirection.Out))
                {
                    pipe.Connect(2000);
                    byte[] buffer = Encoding.Unicode.GetBytes(absolutePath);
                    pipe.Write(buffer, 0, buffer.Length);
                    pipe.Flush();

                    LogToFile($"[IPC] Sent path: {absolutePath}");
                    return true;
                }
            }
            catch (Exception ex)
            {
                LogToFile($"[IPC] Failed to send path: {ex.Message}");
                return false;
            }
        }

        private static void LogToFile(string message)
        {
            try
            {
                string logPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "VettaiyanAppLog.txt");
                File.AppendAllText(logPath, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - {message}{Environment.NewLine}");
            }
            catch { }
        }
    }
}
