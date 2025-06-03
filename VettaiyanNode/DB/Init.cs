
using System.Data.SQLite;

namespace VettaiyanNode.DB
{
    internal class Init
    {
        private static readonly string _dbPath = Common.Global.dbPath;

        public static void Initialize()
        {
            using var connection = new SQLiteConnection($"Data Source={_dbPath}");
            connection.Open();

            if (!TableExists(connection, "ScanStats"))
                CreateScanStatsTable(connection);

            if (!TableExists(connection, "ScanResults"))
                CreateScanResultsTable(connection);
        }

        private static bool TableExists(SQLiteConnection connection, string tableName)
        {
            using var cmd = connection.CreateCommand();
            cmd.CommandText = "SELECT name FROM sqlite_master WHERE type='table' AND name=$table;";
            cmd.Parameters.AddWithValue("$table", tableName);
            using var reader = cmd.ExecuteReader();
            return reader.Read();
        }

        private static void CreateScanStatsTable(SQLiteConnection connection)
        {
            using var cmd = connection.CreateCommand();
            cmd.CommandText = @"
                CREATE TABLE IF NOT EXISTS ScanStats (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ScanType TEXT NOT NULL,
                    Timestamp TEXT NOT NULL DEFAULT (CURRENT_TIMESTAMP),
                    ScanDuration TEXT,
                    ThreatsFound TEXT,
                    FilesScanned TEXT
                );";
            cmd.ExecuteNonQuery();
        }

        private static void CreateScanResultsTable(SQLiteConnection connection)
        {
            using var cmd = connection.CreateCommand();
            cmd.CommandText = @"
                CREATE TABLE IF NOT EXISTS ScanResults (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ruleName TEXT,
                    fileName TEXT,
                    filePath TEXT,
                    fileHash TEXT,
                    fileType TEXT,
                    scanType TEXT,
                    timestamp TEXT DEFAULT (CURRENT_TIMESTAMP),
                    actionTaken TEXT,
                    reason TEXT
                );";
            cmd.ExecuteNonQuery();
        }
    
    }
}
