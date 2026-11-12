"use client";

import * as React from "react";
import { usePathname, useRouter } from "next/navigation";
import { Sidebar } from "@/components/ui/sidebar";
import { Header } from "@/components/ui/header";
import { getAuthSession } from "@/lib/api";

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const [mobileOpen, setMobileOpen] = React.useState(false);
  const [authChecked, setAuthChecked] = React.useState(false);
  const [authed, setAuthed] = React.useState(false);
  const openMenu = React.useCallback(() => setMobileOpen(true), []);
  const closeMenu = React.useCallback(() => setMobileOpen(false), []);

  const isLogin = pathname === "/login";

  React.useEffect(() => {
    let cancelled = false;
    async function check() {
      if (isLogin) {
        setAuthed(false);
        setAuthChecked(true);
        return;
      }
      try {
        await getAuthSession();
        if (!cancelled) {
          setAuthed(true);
          setAuthChecked(true);
        }
      } catch {
        if (!cancelled) {
          setAuthed(false);
          setAuthChecked(true);
          router.replace("/login");
        }
      }
    }
    check();
    return () => { cancelled = true; };
  }, [isLogin, router, pathname]);

  if (isLogin) {
    return <div className="min-h-screen bg-background">{children}</div>;
  }

  if (!authChecked) {
    return <div className="min-h-screen bg-background text-[hsl(var(--muted-foreground))] flex items-center justify-center">Checking session...</div>;
  }

  if (!authed) {
    return null;
  }

  return (
    <div className="flex min-h-screen bg-background">
      <Sidebar mobileOpen={mobileOpen} onClose={closeMenu} />
      <div className="flex min-w-0 flex-1 flex-col lg:pl-64">
        <Header onMenuClick={openMenu} />
        <main className="min-w-0 flex-1 p-4 sm:p-6 md:p-8">{children}</main>
      </div>
    </div>
  );
}
