def ask(qst: str, df: bool) -> bool:
    i=input(f"{qst}? <Def={'YNeos'[1-df::2]}> ").strip().lower()
    if not i: return df
    if df: return i not in ["no","n","nao","0"]
    return i in ["yes","ye","y","si","s","1"]
