import React, { useState, useEffect } from 'react';
import {
  AlertTriangle,
  ShieldCheck,
  FileSearch,
  BarChart3,
  ChevronRight,
  Github,
  Activity,
  Search
} from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
  PieChart,
  Pie
} from 'recharts';

interface Finding {
  id: string;
  message: string;
  file: string;
  line: number;
  snippet: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  ai_explanation: {
    explanation: string;
    remediation: string;
  };
}

interface ScanResponse {
  findings: Finding[];
  count: number;
}

const SEVERITY_COLORS = {
  Critical: '#ef4444',
  High: '#f97316',
  Medium: '#f59e0b',
  Low: '#10b981',
};

const App: React.FC = () => {
  const [targetPath, setTargetPath] = useState('');
  const [findings, setFindings] = useState<Finding[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  const runScan = async () => {
    setIsLoading(true);
    try {
      const response = await fetch('/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_path: targetPath }),
      });
      const data: ScanResponse = await response.json();
      setFindings(data.findings);
    } catch (error) {
      console.error('Scan error:', error);
      alert('Error running scan: ' + error);
    } finally {
      setIsLoading(false);
    }
  };

  const severityCounts = findings.reduce((acc, curr) => {
    acc[curr.severity] = (acc[curr.severity] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const chartData = [
    { name: 'Critical', value: severityCounts['Critical'] || 0, color: SEVERITY_COLORS.Critical },
    { name: 'High', value: severityCounts['High'] || 0, color: SEVERITY_COLORS.High },
    { name: 'Medium', value: severityCounts['Medium'] || 0, color: SEVERITY_COLORS.Medium },
    { name: 'Low', value: severityCounts['Low'] || 0, color: SEVERITY_COLORS.Low },
  ];

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 p-6 font-sans">
      {/* Header */}
      <header className="flex justify-between items-center mb-8 border-b border-slate-700 pb-6">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-indigo-600 rounded-lg">
            <ShieldCheck size={24} className="text-white" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight">SentrySAST <span className="text-slate-500 font-normal">Dashboard</span></h1>
        </div>
        <div className="flex items-center gap-4">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" size={18} />
            <input
              type="text"
              placeholder="Search findings..."
              className="bg-slate-800 border border-slate-700 rounded-md py-2 pl-10 pr-4 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 w-64"
            />
          </div>
          <div className="flex items-center gap-2 text-sm text-slate-400 bg-slate-800 px-3 py-1.5 rounded-full border border-slate-700">
            <Activity size={14} />
            <span>System Healthy</span>
          </div>
        </div>
      </header>

      <div className="grid grid-cols-12 gap-6">
        {/* Left Column: Scan Control & Stats */}
        <div className="col-span-12 lg:col-span-4 space-y-6">
          <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 shadow-sm">
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <FileSearch size={20} className="text-indigo-400" />
              Target Codebase
            </h2>
            <div className="flex gap-2">
              <input
                type="text"
                value={targetPath}
                onChange={(e) => setTargetPath(e.target.value)}
                placeholder="/Users/dhanush/projects/my-app"
                className="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
              />
              <button
                onClick={runScan}
                disabled={isLoading}
                className="bg-indigo-600 hover:bg-indigo-500 disabled:bg-slate-600 transition-colors px-4 py-2 rounded-lg text-sm font-medium"
              >
                {isLoading ? 'Scanning...' : 'Run Scan'}
              </button>
            </div>
          </div>

          <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 shadow-sm">
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <BarChart3 size={20} className="text-indigo-400" />
              Severity Distribution
            </h2>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={chartData} layout="vertical" margin={{ left: -20 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" horizontal={false} />
                  <XAxis type="number" hide />
                  <YAxis
                    dataKey="name"
                    type="category"
                    axisLine={false}
                    tickLine={false}
                    tick={{ fill: '#94a3b8', fontSize: 12 }}
                  />
                  <Tooltip
                    cursor={{ fill: 'rgba(255,255,255,0.05)' }}
                    contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', color: '#f1f5f9' }}
                  />
                  <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                    {chartData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
            <div className="grid grid-cols-2 gap-4 mt-6">
              {chartData.map((item) => (
                <div key={item.name} className="bg-slate-900 p-3 rounded-lg border border-slate-700 flex justify-between items-center">
                  <span className="text-xs text-slate-400 uppercase font-semibold">{item.name}</span>
                  <span className="text-lg font-bold" style={{ color: item.color }}>{item.value}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right Column: Findings List */}
        <div className="col-span-12 lg:col-span-8 space-y-6">
          <div className="bg-slate-800 border border-slate-700 rounded-xl overflow-hidden shadow-sm">
            <div className="flex justify-between items-center p-6 border-b border-slate-700">
              <h2 className="text-lg font-semibold flex items-center gap-2">
                <AlertTriangle size={20} className="text-indigo-400" />
                Security Findings
              </h2>
              <span className="text-sm text-slate-400">{findings.length} issues detected</span>
            </div>
            <div className="overflow-y-auto max-h-[700px]">
              {findings.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-20 text-slate-500">
                  <div className="p-4 bg-slate-900 rounded-full mb-4">
                    <FileSearch size={48} className="text-slate-600" />
                  </div>
                  <p>No findings yet. Run a scan on a target directory.</p>
                </div>
              ) : (
                <div className="grid grid-cols-1 gap-px bg-slate-700">
                  {findings.map((f, idx) => (
                    <div
                      key={idx}
                      onClick={() => setSelectedFinding(f)}
                      className={`group cursor-pointer p-4 hover:bg-slate-700/50 transition-colors flex items-center justify-between ${selectedFinding?.id === f.id ? 'bg-slate-700' : 'bg-slate-800'}`}
                    >
                      <div className="flex items-center gap-4">
                        <div className={`w-2 h-10 rounded-full ${
                          f.severity === 'Critical' ? 'bg-critical' :
                          f.severity === 'High' ? 'bg-high' :
                          f.severity === 'Medium' ? 'bg-medium' : 'bg-low'
                        }`} />
                        <div>
                          <div className="font-medium text-slate-200 group-hover:text-white transition-colors">{f.message}</div>
                          <div className="text-xs text-slate-400 flex items-center gap-1">
                            <FileSearch size={12} />
                            {f.file} <ChevronRight size={12} /> {f.line}
                          </div>
                        </div>
                      </div>
                      <ChevronRight size={18} className="text-slate-500 group-hover:text-slate-300" />
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Finding Detail Modal */}
      {selectedFinding && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-6 bg-slate-900/80 backdrop-blur-sm">
          <div className="bg-slate-800 border border-slate-700 rounded-2xl w-full max-w-4xl max-h-[90vh] overflow-hidden flex flex-col shadow-2xl">
            <div className="flex justify-between items-center p-6 border-b border-slate-700">
              <div className="flex items-center gap-3">
                <div className={`w-3 h-3 rounded-full ${
                  selectedFinding.severity === 'Critical' ? 'bg-critical' :
                  selectedFinding.severity === 'High' ? 'bg-high' :
                  selectedFinding.severity === 'Medium' ? 'bg-medium' : 'bg-low'
                }`} />
                <h3 className="text-xl font-bold">{selectedFinding.message}</h3>
              </div>
              <button
                onClick={() => setSelectedFinding(null)}
                className="p-2 hover:bg-slate-700 rounded-lg transition-colors text-slate-400 hover:text-white"
              >
                <span className="text-2xl">&times;</span>
              </button>
            </div>
            <div className="overflow-y-auto p-6 space-y-6">
              <div className="grid grid-cols-3 gap-6">
                <div className="col-span-2 space-y-4">
                  <div className="bg-slate-900 rounded-lg p-4 border border-slate-700">
                    <div className="flex justify-between items-center mb-2">
                      <span className="text-xs font-bold text-slate-500 uppercase">Code Snippet</span>
                      <span className="text-xs text-slate-400">{selectedFinding.file} : Line {selectedFinding.line}</span>
                    </div>
                    <pre className="text-sm font-mono text-indigo-300 overflow-x-auto p-2">
                      <code>{selectedFinding.snippet}</code>
                    </pre>
                  </div>
                  <div className="bg-slate-900 rounded-lg p-4 border border-slate-700">
                    <div className="flex justify-between items-center mb-2">
                      <span className="text-xs font-bold text-slate-500 uppercase">AI Explanation</span>
                      <span className="text-indigo-400 text-xs font-bold uppercase">Powered by Claude</span>
                    </div>
                    <p className="text-sm text-slate-300 leading-relaxed">
                      {selectedFinding.ai_explanation.explanation}
                    </p>
                  </div>
                </div>
                <div className="col-span-1 space-y-4">
                  <div className="bg-indigo-900/20 rounded-lg p-4 border border-slate-700 border-l-4 border-l-indigo-500">
                    <span className="text-xs font-bold text-slate-500 uppercase mb-2 block">Remediation</span>
                    <p className="text-sm text-slate-300 leading-relaxed">
                      {selectedFinding.ai_explanation.remediation}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default App;
