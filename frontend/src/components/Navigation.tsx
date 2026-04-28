import Link from "next/link";
import { Shield } from "lucide-react";
import { Button } from "@/components/ui/button";
import { SignInButton, SignedIn, SignedOut, UserButton } from "@clerk/nextjs";

export function Navigation() {
  return (
    <header className="sticky top-0 z-50 w-full border-b border-white/10 bg-black/50 backdrop-blur-md">
      <div className="container mx-auto px-4 h-16 flex items-center justify-between">
        <Link href="/" className="flex items-center gap-2 group">
          <div className="w-8 h-8 rounded-lg bg-white/5 border border-white/10 flex items-center justify-center group-hover:border-white/20 transition-colors">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <span className="font-bold text-lg tracking-tight">MCPGuard</span>
        </Link>

        <nav className="flex items-center gap-6">
          <Link
            href="/registry"
            className="text-sm font-medium text-white/60 hover:text-white transition-colors"
          >
            Registry
          </Link>
          <Link
            href="/docs"
            className="text-sm font-medium text-white/60 hover:text-white transition-colors"
          >
            Docs
          </Link>
          
          <div className="h-6 w-px bg-white/10 mx-2" />

          <SignedOut>
            <SignInButton mode="modal">
              <Button variant="secondary" size="sm">
                Sign In
              </Button>
            </SignInButton>
          </SignedOut>
          <SignedIn>
            <UserButton appearance={{ elements: { userButtonAvatarBox: "w-8 h-8" } }} />
          </SignedIn>

          <Button variant="outline" size="sm" asChild className="ml-2 border-white/10 bg-white/5 hover:bg-white/10">
            <Link href="https://github.com/mudbbir23/MCPGuard" target="_blank">
              GitHub
            </Link>
          </Button>
        </nav>
      </div>
    </header>
  );
}
