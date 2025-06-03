using System;
using System.Threading.Tasks;
using System.Data.SQLite;

namespace VettaiyanNode.DB
{
    public class ScanStats
    {
        private static readonly string _dbPath = Common.Global.dbPath;

        public static async Task SaveScanAsync(string scanType, string scanDuration, string threatsFound, string filesScanned)
        {
            using var connection = new SQLiteConnection($"Data Source={_dbPath}");
            await connection.OpenAsync();

            var command = connection.CreateCommand();
            command.CommandText =
                "INSERT INTO ScanStats (ScanType, Timestamp, ScanDuration, ThreatsFound, FilesScanned) " +
                "VALUES ($scanType, $timestamp, $scanDuration, $threatsFound, $filesScanned);";

            command.Parameters.AddWithValue("$scanType", scanType);
            command.Parameters.AddWithValue("$timestamp", DateTime.Now.ToString("g"));
            command.Parameters.AddWithValue("$scanDuration", scanDuration);
            command.Parameters.AddWithValue("$threatsFound", threatsFound);
            command.Parameters.AddWithValue("$filesScanned", filesScanned);

            await command.ExecuteNonQueryAsync();
        }

        public static async Task<(string Timestamp, string ScanType, string Duration, string ThreatsFound, string FilesScanned)> GetLatestScanAsync()
        {
            using var connection = new SQLiteConnection($"Data Source={_dbPath}");
            await connection.OpenAsync();

            var command = connection.CreateCommand();
            command.CommandText =
                "SELECT Timestamp, ScanType, ScanDuration, ThreatsFound, FilesScanned " +
                "FROM ScanStats ORDER BY Id DESC LIMIT 1";

            using var reader = await command.ExecuteReaderAsync();
            if (await reader.ReadAsync())
            {
                return (
                    reader.GetString(0),
                    reader.GetString(1),
                    reader.GetString(2),
                    reader.GetString(3),
                    reader.GetString(4)
                );
            }

            return ("N/A", "N/A", "N/A", "0", "0");
        }
    }
}
