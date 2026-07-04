import matplotlib.pyplot as plt
import matplotlib.animation as animation
import pandas as pd
import os
from collections import defaultdict

# setup figure
fig, (ax1, ax2) = plt.subplots(1,2, figsize=(14,6))
fig.suptitle("Lightweight Anomaly-based IDS Dashboard", fontsize=14, fontweight="bold")

def update(frame):
    # --- LEFT PANEL: live traffic ---
    ax1.clear()
    ax1.set_title("Live Packet Count per IP")
    ax1.set_xlabel("Source IP")
    ax1.set_ylabel("Packet Count")

    if os.path.exists("alerts.csv"):
        try:
            df = pd.read_csv("alerts.csv", names=["Timestamp", "Source IP", "Anomaly Type", "Value"], header=0)

            if not df.empty:
                # count alerts per IP
                ip_counts = df["Source IP"].value_counts()
                colors = ["red" if t== "DOS / TRAFFIC SPIKE" else "orange" for t in df.groupby("Source IP")["Anomaly Type"].first()[ip_counts.index]]

                ax1.bar(ip_counts.index, ip_counts.values, color=colors)
                ax1.tick_params(axis="x", rotation=45)

            else:
                ax1.text(0.5, 0.5, "No alerts yet", ha="center", va="center", transform=ax1.transAxes)

        except Exception as e:
            print("ERROR:", e)
            ax1.text(0.5,0.5, "Waiting for data ...", ha="center",va="center", transform=ax1.transAxes)
    else:
        ax1.text(0.5, 0.5, "No alerts yet", ha="center", va="center", transform=ax1.transAxes)

# ---Right Panel: alert log ---
    ax2.clear()
    ax2.set_title("Alert Log")
    ax2.axis("off")
 
    if os.path.exists("alerts.csv"):
        try:
            df = pd.read_csv("alerts.csv", names=["Timestamp", "Source IP", "Anomaly Type", "Value"], header=0)

            if not df.empty:
                # show last 10 alerts
                recent = df.tail(10).reset_index(drop=True)
                table_data=[]
                for _, row in recent.iterrows():
                    table_data.append([
                        str(row["Timestamp"])[-8:],
                        str(row["Source IP"]),
                        str(row["Anomaly Type"]),
                        str(row["Value"])
                    ])

                    table = ax2.table(
                        cellText=table_data,
                        colLabels=["Time", "Source IP", "Type", "Value"],
                        loc="center",
                        cellLoc="center")
                    table.auto_set_font_size(False)
                    table.set_fontsize(9)
                    table.scale(1.2,1.8)

                     # color rows by type
                for i, row in enumerate(recent.itertuples()):
                    color = "#ffcccc" if row._3 == "DOS / TRAFFIC SPIKE" else "#ffe0b2"
                    for j in range(4):
                        table[i + 1, j].set_facecolor(color)
            else:
                 ax2.text(0.5, 0.5, "No alerts yet", ha="center", va="center", transform=ax2.transAxes)
        except Exception as e:
            print("Error:",e)
            ax2.text(0.5, 0.5, "Waiting for data..", ha="center", va="center", transform=ax2.transAxes)
    else:
        ax1.text(0.5, 0.5, "No alerts logged yet", ha="center", va="center", transform=ax2.transAxes)
    plt.tight_layout()

ani=animation.FuncAnimation(fig, update, interval=3000)
plt.show()
