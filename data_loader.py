import pandas as pd


def load_cicids_dataset(file_path, rows=5000):
    print("📂 Loading CICIDS dataset...")

    df = pd.read_csv(file_path, nrows=rows)

    print("✅ Dataset loaded successfully")
    print("Rows loaded:", len(df))
    print("Columns:")
    print(df.columns.tolist())

    return df