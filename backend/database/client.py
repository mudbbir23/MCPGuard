"""
Supabase Database Client
"""

import os
from supabase import create_client, Client

SUPABASE_URL = os.getenv("SUPABASE_URL")
# Prefer service role key for backend operations so we bypass RLS where necessary,
# but fallback to anon key if service role is not provided.
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_ANON_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    # Dummy client for local development if keys are not set yet
    print("WARNING: SUPABASE_URL or keys not set. Supabase client will fail on queries.")
    
def get_supabase() -> Client:
    """Returns a configured Supabase client."""
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise ValueError("Supabase configuration missing (SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)")
    return create_client(SUPABASE_URL, SUPABASE_KEY)
