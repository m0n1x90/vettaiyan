using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VettaiyanNode.Model
{
    public class Threat
    {
        public string ThreatID { get; set; }
        public string ThreatName { get; set; }
        public string ThreatImageName { get; set; }
        public string ThreatImagePath { get; set; }
        public string ThreatImageHash { get; set; }
        public string ThreatImageType { get; set; }
        public string ScaneType { get; set; }
        public string TimeDetected { get; set; }
        public string ActionTaken { get; set; }
    }
}
