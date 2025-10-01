from sentence_transformers import SentenceTransformer
import pandas as pd
import pathlib
import torch
import json

model = SentenceTransformer("CyCraftAI/CmdCaliper-large", device="cuda").to("cuda")

def preprocessing():
    print(torch.cuda.is_available())
    print(torch.cuda.device_count())
    print(torch.cuda.get_device_name(0))
    print(torch.cuda.current_device())

def main(folder = "./Data"):
    sentences = []
    data_info = {}
    folder = pathlib.Path(folder)
    # Load the sentences from the UCSC_HDS.parquet file
    for p in folder.rglob(f"*.json"):
            if not p.is_file():
                continue
            # Only process files whose parent folder or any part of their path is "LLM Jury"
            if "LLM Jury" not in str(p.parent) and "LLM Jury" not in str(p):
                continue
            try:
                raw = p.read_text(encoding="utf-8")
            except Exception as e:
                print(f"ERROR: Could not read {p}: {e}")
                continue

            # Parse JSON
            try:
                data = json.loads(raw)
            except Exception as e:
                print(f"ERROR: Could not parse JSON from {p}: {e}")
                continue

            command_field = data.get("command")
            sentences.append(command_field)

    embeddings = model.encode(sentences)
    print(embeddings.shape)
    # [3, 768]

    # Get the similarity scores for the embeddings
    model.cuda( )
    similarities = model.similarity(embeddings, embeddings)
    # Save the similarity matrix to a CSV file
    similarity_df = pd.DataFrame(similarities.cpu().numpy())
    similarity_df.to_csv(folder / "similarity_matrix.csv", index=False)
    

    # Load the similarity matrix from the CSV file
    #similarity_df = pd.read_csv("C:\\Users\\flacman\\Documents\\luni\\UCSC\\Project\\BNTBD2\\CmdCaliper\\similarity_matrix.csv")
    similarities = similarity_df.values

    # Remove sentences with more than 99 similarity score (excluding self-similarity where i = j)

    to_remove = set()
    duplicated = 0

    # Iterate through the similarity matrix and mark duplicates
    for i in range(len(similarities)):
        for j in range(i + 1, len(similarities)):
            similarity_score = float(similarities[i][j])
            if similarity_score > 0.95:
                if i < j:
                    to_remove.add(i)
                    duplicated += 1
                    data_info[i] = {
                        "Duplicated": 1,
                        "ComparedTo": int(j),
                        "RemovedSentence": sentences[i],
                        "ComparedSentence": sentences[j],
                        "SimilarityScore": similarity_score
                    }
                    break

    # Filter out the sentences to remove

    filtered_data = [s for idx, s in enumerate(sentences) if idx not in to_remove]

    # Save the removed sentences (those in to_remove) to a JSON file
    removed_sentences = [sentences[idx] for idx in sorted(to_remove)]
    with open(folder / "removed_sentences.json", "w", encoding="utf-8") as f:
        json.dump(removed_sentences, f, ensure_ascii=False, indent=2)

    with open(folder / "data_info.json", "w", encoding="utf-8") as f:
        json.dump(data_info, f, ensure_ascii=False, indent=2)

    # Calculate and collect statistics
    stats_lines = []
    initial_row_count = len(sentences)
    filtered_row_count = len(filtered_data)
    removed_row_count = initial_row_count - filtered_row_count
    if initial_row_count == 0:
        stats_lines.append("No data found.")
        print("\n".join(stats_lines))
        with open(folder / "statistics.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(stats_lines))
        return

    stats_lines.append(f"Initial number of rows: {initial_row_count}")
    stats_lines.append(f"Number of rows after filtering: {filtered_row_count}")
    stats_lines.append(f"Number of rows removed: {removed_row_count}")
    stats_lines.append(f"Number of rows marked as duplicated: {duplicated}")
    stats_lines.append(f"Percentage of rows removed: {removed_row_count / initial_row_count * 100:.2f}%")

    # Calculate similarity statistics for removed rows
    removed_similarities = []
    for i in range(len(similarities)):
        for j in range(i + 1, len(similarities)):
            if j in to_remove and similarities[i][j] > 0.95:
                removed_similarities.append(similarities[i][j])

    if removed_similarities:
        avg_removed_similarity = sum(removed_similarities) / len(removed_similarities)
        max_removed_similarity = max(removed_similarities)
        min_removed_similarity = min(removed_similarities)
        stats_lines.append(f"Average similarity of removed rows: {avg_removed_similarity:.2f}")
        stats_lines.append(f"Highest similarity of removed rows: {max_removed_similarity:.2f}")
        stats_lines.append(f"Lowest similarity of removed rows: {min_removed_similarity:.2f}")
    else:
        stats_lines.append("No rows were removed based on similarity threshold.")

    # Overall similarity statistics
    max_similarity = similarities.max()
    min_similarity = similarities.min()
    stats_lines.append(f"Highest similarity value in the matrix: {max_similarity:.2f}")
    stats_lines.append(f"Lowest similarity value in the matrix: {min_similarity:.2f}")

    # Print and save statistics to file
    print("\n".join(stats_lines))
    with open(folder / "statistics.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(stats_lines))

if __name__ == "__main__":
    preprocessing()
    for subfolder in pathlib.Path("./Data/Samples").iterdir():
        if subfolder.is_dir():

            main(subfolder)
    main("./Data")