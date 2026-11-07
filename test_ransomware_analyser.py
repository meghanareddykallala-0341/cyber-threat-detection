
from app.ransomware_analyser import analyze_ransomware_csv

file_path = "datasets/SILRAD/fasttext-testmodel.csv"

result = analyze_ransomware_csv(file_path)

print(result)
