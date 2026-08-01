// ```ts file="src/…#region" のコードフェンスを、現在の実ソース片に置換する
// remark プラグイン。doc にコードを手書きコピーせず常に最新を取り込む。
import { sourceRegion } from "../lib/extract";

interface MdNode {
  type: string;
  meta?: string | null;
  value?: string;
  children?: MdNode[];
}

const walk = (node: MdNode): void => {
  if (node.type === "code" && typeof node.meta === "string") {
    const m = /file="([^"#]+)#([^"]+)"/.exec(node.meta);
    if (m) node.value = sourceRegion(m[1], m[2]); // region 欠落なら throw → ビルドが落ちる
  }
  node.children?.forEach(walk);
};

export default function remarkCodeRegion() {
  return (tree: MdNode): void => walk(tree);
}
