using System;
using System.Collections.Generic;
using System.Data.SQLite;
using VettaiyanNode.Model;

namespace VettaiyanNode.DB
{
    public class ScanResults
    {
        private static readonly string _dbPath = Common.Global.dbPath;

        public static int GetTotalThreatCount(string dbPath)
        {
            int count = 0;
            try
            {
                using var conn = new SQLiteConnection($"Data Source={dbPath};Version=3;");
                conn.Open();

                string query = "SELECT COUNT(*) FROM ScanResults";
                using var cmd = new SQLiteCommand(query, conn);
                count = Convert.ToInt32(cmd.ExecuteScalar());

                conn.Close();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine("DB Error (Count): " + ex.Message);
            }
            return count;
        }


        public static List<Threat> LoadRecentThreatsFromDb(string dbPath, int limit = 5)
            {
                var recentThreats = new List<Threat>();

                try
                {
                    using var connection = new SQLiteConnection($"Data Source={dbPath};Version=3;");
                    connection.Open();

                    string query = $@"
                    SELECT id, ruleName, fileName, filePath, fileHash, fileType, scanType, timestamp, actionTaken
                    FROM ScanResults
                    ORDER BY timestamp DESC
                    LIMIT {limit};";

                    using var command = new SQLiteCommand(query, connection);
                    using var reader = command.ExecuteReader();

                    while (reader.Read())
                    {
                        recentThreats.Add(new Threat
                        {
                            ThreatID = reader["id"].ToString(),
                            ThreatName = reader["ruleName"].ToString(),
                            ThreatImageName = reader["fileName"].ToString(),
                            ThreatImagePath = reader["filePath"].ToString(),
                            ThreatImageHash = reader["fileHash"].ToString(),
                            ThreatImageType = reader["fileType"].ToString(),
                            ScaneType = reader["scanType"].ToString(),
                            TimeDetected = reader["timestamp"].ToString(),
                            ActionTaken = reader["actionTaken"].ToString()
                        });
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine("DB Error: " + ex.Message);
                }

                return recentThreats;
            }

        public static List<Threat> LoadRecentThreatsFromDbPaged(string dbPath, int limit, int offset)
        {
            var threats = new List<Threat>();
            try
            {
                using var conn = new SQLiteConnection($"Data Source={dbPath};Version=3;");
                conn.Open();

                string query = "SELECT id, ruleName, fileName, filePath, fileHash, fileType, scanType, timestamp, actionTaken FROM ScanResults ORDER BY timestamp DESC LIMIT @limit OFFSET @offset";
                var cmd = new SQLiteCommand(query, conn);
                cmd.Parameters.AddWithValue("@limit", limit);
                cmd.Parameters.AddWithValue("@offset", offset);

                using var reader = cmd.ExecuteReader();

                while (reader.Read())
                {
                    threats.Add(new Threat
                    {
                        ThreatID = reader["id"].ToString(),
                        ThreatName = reader["ruleName"].ToString(),
                        ThreatImageName = reader["fileName"].ToString(),
                        ThreatImagePath = reader["filePath"].ToString(),
                        ThreatImageHash = reader["fileHash"].ToString(),
                        ThreatImageType = reader["fileType"].ToString(),
                        ScaneType = reader["scanType"].ToString(),
                        TimeDetected = reader["timestamp"].ToString(),
                        ActionTaken = reader["actionTaken"].ToString()
                    });
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine("DB Error: " + ex.Message);
                System.Diagnostics.Debug.WriteLine("Stack Trace: " + ex.StackTrace);
            }

            return threats;
        }


    }
}
