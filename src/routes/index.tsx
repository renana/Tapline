import { createFileRoute } from "@tanstack/react-router";
import { Dashboard } from "@/components/tapline/dashboard";
import { getTrafficDetail, getTrafficSnapshot } from "@/lib/proxy/actions";

export const Route = createFileRoute("/")({
  loader: async () => {
    const snapshot = await getTrafficSnapshot();
    const firstId = snapshot.logs[0]?.id;
    const detail = firstId
      ? await getTrafficDetail({ data: { id: firstId } })
      : null;
    return { snapshot, detail };
  },
  component: Home,
});

function Home() {
  const { snapshot, detail } = Route.useLoaderData();
  return <Dashboard initial={snapshot} initialDetail={detail} />;
}
