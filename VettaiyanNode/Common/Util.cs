using System;

namespace VettaiyanNode.Common
{
    public class Util
    {
        public static string GetQueryParam(Uri uri, string key)
        {
            try
            {
                var query = uri.Query.TrimStart('?');
                var pairs = query.Split('&', StringSplitOptions.RemoveEmptyEntries);
                foreach (var pair in pairs)
                {
                    var kv = pair.Split('=');
                    if (kv.Length == 2 && kv[0].Equals(key, StringComparison.OrdinalIgnoreCase))
                    {
                        return Uri.UnescapeDataString(kv[1]);
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[QueryParam] Error parsing '{key}': {ex.Message}");
            }

            return null;
        }
    }
}
