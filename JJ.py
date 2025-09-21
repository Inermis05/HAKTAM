import hashlib
import json
import time
from collections import Counter, defaultdict

# 블록 기본 클래스
class Block:
    def __init__(self, chain_id, height, producer, payload, prev_hash=""):
        self.chain_id = chain_id
        self.height = height
        self.producer = producer
        self.payload = payload
        self.timestamp = time.time()
        self.prev_hash = prev_hash
        content = f"{chain_id}|{height}|{producer}|{json.dumps(payload)}|{self.timestamp}|{prev_hash}"
        self.hash = hashlib.sha256(content.encode()).hexdigest()[:12]

# 서브체인 투표 노드: 여러 지역 투표 결과를 블록으로 만듦
class SubChainNode:
    def __init__(self, node_id, candidates, vote_counts):
        self.node_id = node_id
        self.candidates = candidates
        self.vote_counts = vote_counts
        self.chain = []

    def produce_vote_block(self):
        height = len(self.chain) + 1
        payload = {
            "vote_counts": self.vote_counts
        }
        prev = self.chain[-1].hash if self.chain else ""
        block = Block(self.node_id, height, self.node_id, payload, prev)
        self.chain.append(block)
        return block

# 메인 노드: 여러 서브체인 투표 블록을 모아서 합산하고 PoS 기반 마이닝
class MainNode:
    def __init__(self, node_id, candidates, stake):
        self.node_id = node_id
        self.candidates = candidates
        self.stake = stake
        self.chain = []

    def aggregate_votes(self, subchain_blocks):
        total_votes = Counter()
        for blk in subchain_blocks:
            total_votes.update(blk.payload["vote_counts"])
        max_votes = max(total_votes.values())
        winners = [c for c,v in total_votes.items() if v==max_votes]
        return winners, dict(total_votes)

    def mine_block(self, aggregation):
        height = len(self.chain) + 1
        payload = aggregation
        prev = self.chain[-1].hash if self.chain else ""
        block = Block(self.node_id, height, self.node_id, payload, prev)
        self.chain.append(block)
        return block

# 실행 예시
if __name__ == "__main__":
    candidates = ['A', 'B', 'C']

    # 서브체인 노드1: 투표결과
    subnode1 = SubChainNode("Region1", candidates, {'A':3, 'B':2, 'C':1})
    blk1 = subnode1.produce_vote_block()

    # 서브체인 노드2: 투표결과
    subnode2 = SubChainNode("Region2", candidates, {'A':1, 'B':4, 'C':1})
    blk2 = subnode2.produce_vote_block()

    # 메인 노드: 각 서브체인 블록 집계 및 마이닝
    main_node = MainNode("MainNode", candidates, stake=100)
    winners, total_votes = main_node.aggregate_votes([blk1, blk2])
    main_block = main_node.mine_block({
        "total_votes": total_votes,
        "winners": winners
    })

    print("최종 집계 투표수:", total_votes)
    print("최종 승자:", winners)
    print("메인체인 블록 해시:", main_block.hash)
