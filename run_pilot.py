import os, argparse, pathlib

import pandas as pd

from download_ri_csv import download_csv
from enrich_websites_and_emails import enrich

RAW = "data/raw/ri_ef_funeral_establishments.csv"
OUT = "data/processed/warwick_funeral_homes.csv"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--force-download", action="store_true")
    args = parser.parse_args()

    if args.force_download or not pathlib.Path(RAW).exists():
        import asyncio
        asyncio.run(download_csv(RAW))
    
    df = pd.read_csv(RAW)
    # Filter to Warwick, normalize columns if needed
    df = df[df["City"].astype(str).str.strip().str.lower() == "warwick"].copy()
    # Deduplicate by Name + Address
    df["__key"] = (df["Name"].str.strip().str.lower() + "|" + df["License Address Line 1"].astype(str).str.strip().str.lower())
    df = df.drop_duplicates("__key").drop(columns="__key")

    out = enrich(df)
    pathlib.Path("data/processed").mkdir(parents=True, exist_ok=True)
    out.to_csv(OUT, index=False)
    print(f"Wrote {OUT} with {len(out)} rows")

if __name__ == "__main__":
    main()