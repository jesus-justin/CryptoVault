import { useEffect, useState } from 'react';
import { getApi } from '../lib/api';

interface AlgorithmMeta {
  name: string;
  status: string;
  category: string;
}

export default function Dashboard() {
  const [algorithms, setAlgorithms] = useState<AlgorithmMeta[]>([]);

  useEffect(() => {
    void (async () => {
      const response = await getApi<{
        success: boolean;
        data: AlgorithmMeta[];
      }>('/algorithms');

      if (response.success) {
        setAlgorithms(response.data);
      }
    })();
  }, []);

  const total = algorithms.length;
  const recommended = algorithms.filter((entry) => entry.status === 'recommended').length;
  const legacy = algorithms.filter((entry) => entry.status === 'legacy').length;
  const deprecated = algorithms.filter((entry) => entry.status === 'deprecated').length;

  return (
    <section className="space-y-6 p-6">
      <h1 className="text-2xl font-bold text-slate-900">Dashboard</h1>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <div className="rounded-2xl border border-slate-200 bg-white p-4">
          <p className="text-xs uppercase text-slate-500">Total Algorithms</p>
          <p className="mt-2 text-3xl font-bold text-slate-900">{total}</p>
        </div>
        <div className="rounded-2xl border border-emerald-200 bg-emerald-50 p-4">
          <p className="text-xs uppercase text-emerald-700">Recommended</p>
          <p className="mt-2 text-3xl font-bold text-emerald-900">{recommended}</p>
        </div>
        <div className="rounded-2xl border border-amber-200 bg-amber-50 p-4">
          <p className="text-xs uppercase text-amber-700">Legacy</p>
          <p className="mt-2 text-3xl font-bold text-amber-900">{legacy}</p>
        </div>
        <div className="rounded-2xl border border-rose-200 bg-rose-50 p-4">
          <p className="text-xs uppercase text-rose-700">Deprecated</p>
          <p className="mt-2 text-3xl font-bold text-rose-900">{deprecated}</p>
        </div>
      </div>

      <div className="rounded-2xl border border-slate-200 bg-white p-4">
        <h2 className="mb-3 text-lg font-semibold text-slate-900">Algorithm Usage Map</h2>
        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
          {algorithms.map((entry) => (
            <div key={`${entry.category}-${entry.name}`} className="rounded-lg border border-slate-100 bg-slate-50 px-3 py-2 text-sm">
              <p className="font-semibold text-slate-900">{entry.name}</p>
              <p className="text-xs uppercase text-slate-500">{entry.category}</p>
              <p className="text-xs text-slate-700">{entry.status}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
