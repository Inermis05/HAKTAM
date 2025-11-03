import random

class Node:
    # 개별 노드
    def __init__(self, node_id):
        self.id = node_id
        self.trust_score = 0.5

    def update_trust_score(self, voted_for_winner, change=0.05):
        # 신뢰도 시스템
        if voted_for_winner:
            self.trust_score += change
        else:
            self.trust_score -= change
        
        self.trust_score = max(0.0, min(1.0, self.trust_score))

    def __repr__(self):
        return f"Node(id={self.id}, trust={self.trust_score:.2f})"

class LowerChain:
    # 하위체인 클래스
    def __init__(self, chain_id, nodes):
        self.id = chain_id
        self.nodes = nodes

    def tally_internal_votes(self, all_votes, candidates, malicious_threshold):
        # 노드 집계
        internal_tally = {candidate: 0 for candidate in candidates}
        valid_nodes = []
        print(f"  -- Tallying for Lower Chain {self.id} --")
        for node in self.nodes:
            choice = all_votes[node.id]
            is_malicious = node.trust_score <= malicious_threshold
            print(f"    Node {node.id} (trust: {node.trust_score:.2f}) votes for {choice}", end="")
            if not is_malicious:
                internal_tally[choice] += 1
                valid_nodes.append(node)
                print("")
            else:
                print(" (Vote not counted - Malicious)")
        return internal_tally, valid_nodes

class BlockchainSimulator:
    # 상위노드 하위노드 구현
    def __init__(self, chain_setup, candidates):
        self.all_nodes = [Node(i) for i in range(sum(len(nodes) for nodes in chain_setup))]
        self.lower_chains = []
        node_idx = 0
        for i, node_ids in enumerate(chain_setup):
            chain_nodes = [self.all_nodes[node_idx + j] for j in range(len(node_ids))]
            self.lower_chains.append(LowerChain(chain_id=i, nodes=chain_nodes))
            node_idx += len(node_ids)
            
        self.candidates = candidates
        self.malicious_threshold = 0.25

    def print_status(self):
        # 신뢰도 출력
        print("--- Node Status ---")
        for chain in self.lower_chains:
            print(f"  Lower Chain {chain.id}:")
            for node in chain.nodes:
                print(f"    {node}")
        print("--------------------")

    def run_round(self, round_num, votes_cast):
        # 한 라운드 투표 실행
        print(f"\n========== Round {round_num} Start ==========")
        self.print_status()

        # 1. 각 하위 체인별로 내부 투표 집계 (PDF 4장 방식 적용)
        print("\n--- 1. Lower Chain Internal Tally & Weighting ---")
        final_tally = {candidate: 0.0 for candidate in self.candidates}
        for chain in self.lower_chains:
            internal_result, valid_nodes = chain.tally_internal_votes(votes_cast, self.candidates, self.malicious_threshold)
            
            total_valid_votes = sum(internal_result.values())
            
            if total_valid_votes > 0:
                # 체인의 평균 신뢰도 계산
                avg_credibility = sum(node.trust_score for node in chain.nodes) / len(chain.nodes)
                print(f"  Chain {chain.id}: Total Valid Votes = {total_valid_votes}, Avg Credibility = {avg_credibility:.2f}")

                # 비율 기반 가중치 적용
                for candidate, votes in internal_result.items():
                    vote_ratio = votes / total_valid_votes
                    weighted_score = vote_ratio * avg_credibility
                    final_tally[candidate] += weighted_score
                    print(f"    {candidate}: Ratio={vote_ratio:.2f}, Weighted Score={weighted_score:.2f}")
            else:
                print(f"  Chain {chain.id}: No valid votes.")


        # 2. 상위 체인에서 최종 결과 합산
        print("\n--- 2. Upper Chain Final Tally (Weighted Scores) ---")
        for candidate, score in final_tally.items():
            print(f"  {candidate}: {score:.4f} score")

        # 3. 승자 결정
        max_score = max(final_tally.values())
        winners = [c for c, v in final_tally.items() if v == max_score]

        if len(winners) == 1:
            final_winner = winners[0]
            print(f"\nWinner is {final_winner}")
        else:
            # 동점자 처리 로직은 기존 방식을 유지 (PDF 4장의 핵심은 집계 방식)
            print(f"\nTie between: {winners}. Applying original tie-breaking rules...")
            final_winner = self._handle_tie(winners, votes_cast)
            print(f"Final Winner after tie-break is {final_winner}")

        # 4. 모든 노드의 신뢰도 업데이트
        for node in self.all_nodes:
            voted_for = votes_cast[node.id]
            node.update_trust_score(voted_for == final_winner)
        
        print(f"\n========== Round {round_num} End ==========")
        self.print_status()

    def _handle_tie(self, tied_candidates, votes):
        
        print("  1. Checking sum of trust scores...")
        trust_sums = {c: 0 for c in tied_candidates}
        for node_id, choice in votes.items():
            if choice in trust_sums:
                trust_sums[choice] += self.all_nodes[node_id].trust_score
        max_trust_sum = max(trust_sums.values())
        potential_winners = [c for c, s in trust_sums.items() if s == max_trust_sum]
        if len(potential_winners) == 1: return potential_winners[0]

        print("  2. Checking number of 1.0 trust nodes...")
        one_trust_counts = {c: 0 for c in potential_winners}
        for node_id, choice in votes.items():
            if choice in one_trust_counts and self.all_nodes[node_id].trust_score == 1.0:
                one_trust_counts[choice] += 1
        max_one_trust_count = max(one_trust_counts.values())
        potential_winners_2 = [c for c, count in one_trust_counts.items() if count == max_one_trust_count]
        if len(potential_winners_2) == 1: return potential_winners_2[0]

        print("  3. Checking for highest trust voter...")
        highest_trust_voter = None; highest_trust_score = -1.0
        for node_id, choice in votes.items():
            if choice in potential_winners_2:
                node_score = self.all_nodes[node_id].trust_score
                if node_score > highest_trust_score: highest_trust_score = node_score; highest_trust_voter = self.all_nodes[node_id]
        voters_with_highest_score = [node for node in self.all_nodes if node.trust_score == highest_trust_score and votes[node.id] in potential_winners_2]
        if len(voters_with_highest_score) == 1: return votes[highest_trust_voter.id]
        
        print("  Could not resolve tie. Defaulting to first candidate.")
        return potential_winners_2[0]

# --- 시뮬레이션 실행 ---
if __name__ == "__main__":
    # 설정
    CANDIDATES = ['A', 'B', 'C']
    NUM_NODES = 100
    NUM_CHAINS = 10
    NODES_PER_CHAIN = NUM_NODES // NUM_CHAINS

    # 하위 체인 구조 동적 생성 (10개 체인, 각 10개 노드)
    CHAIN_SETUP = []
    node_counter = 0
    for i in range(NUM_CHAINS):
        chain = list(range(node_counter, node_counter + NODES_PER_CHAIN))
        CHAIN_SETUP.append(chain)
        node_counter += NODES_PER_CHAIN
    
    sim = BlockchainSimulator(CHAIN_SETUP, CANDIDATES)

    # 5라운드 동안 무작위 투표로 시뮬레이션 실행
    NUM_ROUNDS = 20
    for i in range(NUM_ROUNDS):
        # 100개 노드에 대한 무작위 투표 생성
        votes = {node_id: random.choice(CANDIDATES) for node_id in range(NUM_NODES)}
        sim.run_round(round_num=i + 1, votes_cast=votes)