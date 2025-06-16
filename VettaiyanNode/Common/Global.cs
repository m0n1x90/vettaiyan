using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VettaiyanNode.Common
{
    class Global
    {
        public static readonly string dbPath = Path.Combine(AppContext.BaseDirectory, "data.db");

        public static readonly string scannerPipeName = @"\\.\pipe\VettaiyanScanner";


    }
}
